"""Alert evaluation and dispatch."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import List

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.core.logging import configure_logging, get_logger
from app.models.alert import Alert, AlertChannel, AlertRule, AlertSeverity, AlertStatus
from app.models.vulnerability import Correlation, CorrelationStatus, Severity
from app.services.notify import dispatch_alert
from app.utils.scoring import severity_rank
from app.workers.celery_app import celery_app

configure_logging()
log = get_logger(__name__)


def _matches_rule(rule: AlertRule, c: Correlation, server, cve) -> bool:
    if not rule.enabled:
        return False
    if severity_rank(c.severity) < severity_rank(rule.min_severity):
        return False
    if rule.require_kev and not cve.kev:
        return False
    if rule.require_exploit and not cve.exploit_available:
        return False
    if rule.environments and (server.environment.value not in rule.environments):
        return False
    if rule.os_filter and (server.os_family.value not in rule.os_filter):
        return False
    return True


async def _evaluate_correlation(corr_id) -> int:
    """Generate Alert rows for a single correlation if rules match."""
    created = 0
    async with AsyncSessionLocal() as db:
        c = (await db.execute(
            select(Correlation)
            .where(Correlation.id == corr_id)
            .options(selectinload(Correlation.cve), selectinload(Correlation.server))
        )).scalar_one_or_none()
        if not c or c.status != CorrelationStatus.open:
            return 0
        rules = (await db.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))).scalars().all()
        for rule in rules:
            if not _matches_rule(rule, c, c.server, c.cve):
                continue

            # Cooldown — don't re-alert same correlation within window
            cutoff = datetime.utcnow() - timedelta(minutes=rule.cooldown_minutes)
            recent = (await db.execute(
                select(Alert).where(
                    Alert.correlation_id == c.id,
                    Alert.rule_id == rule.id,
                    Alert.created_at >= cutoff,
                )
            )).scalar_one_or_none()
            if recent:
                continue

            sev_map = {Severity.critical: AlertSeverity.critical, Severity.high: AlertSeverity.high,
                       Severity.medium: AlertSeverity.medium, Severity.low: AlertSeverity.low,
                       Severity.none: AlertSeverity.info}
            for ch in rule.channels:
                try:
                    channel = AlertChannel(ch)
                except ValueError:
                    continue
                title = f"[{c.severity.value.upper()}] {c.cve.cve_id} on {c.server.hostname}"
                body = (f"Server {c.server.hostname} ({c.server.os_family.value}) is affected by "
                        f"{c.cve.cve_id} (CVSS {c.cve.cvss_score or 'n/a'}). "
                        f"Package {c.package_name} {c.installed_version} "
                        f"-> fixed in {c.fixed_version or 'no fix yet'}.")
                a = Alert(
                    rule_id=rule.id,
                    correlation_id=c.id,
                    cve_pk=c.cve.id,
                    server_id=c.server.id,
                    severity=sev_map.get(c.severity, AlertSeverity.info),
                    title=title,
                    body=body,
                    channel=channel,
                    status=AlertStatus.pending,
                    payload={
                        "rule": rule.name,
                        "cve_id": c.cve.cve_id,
                        "cvss": c.cve.cvss_score,
                        "kev": c.cve.kev,
                        "exploit_available": c.cve.exploit_available,
                        "package": c.package_name,
                        "installed": c.installed_version,
                        "fixed_version": c.fixed_version,
                        "hostname": c.server.hostname,
                        "ip": c.server.ip_address,
                        "os": c.server.os_family.value,
                        "environment": c.server.environment.value,
                        "recipients": rule.recipients or {},
                    },
                )
                db.add(a)
                created += 1
        if created:
            await db.commit()
    return created


@celery_app.task(name="alerts.evaluate_correlation")
def evaluate_correlation(corr_id: str) -> int:
    import uuid
    return asyncio.run(_evaluate_correlation(uuid.UUID(corr_id)))


async def _dispatch_pending(limit: int = 100) -> dict:
    sent, failed = 0, 0
    async with AsyncSessionLocal() as db:
        pending = (await db.execute(
            select(Alert)
            .where(Alert.status == AlertStatus.pending)
            .order_by(Alert.severity.desc(), Alert.created_at.asc())
            .limit(limit)
        )).scalars().all()
        for a in pending:
            channel = a.channel.value
            recipients = (a.payload or {}).get("recipients", {}) or {}
            target = _resolve_target(channel, recipients)
            if not target:
                a.status = AlertStatus.failed
                a.error = f"no_target_for_channel:{channel}"
                failed += 1
                continue
            payload = _build_notify_payload(a)
            try:
                result = await dispatch_alert(channel, target, payload)
                if result.get("ok"):
                    a.status = AlertStatus.sent
                    a.sent_at = datetime.utcnow()
                    sent += 1
                else:
                    a.status = AlertStatus.failed
                    a.error = (result.get("error") or "unknown")[:1000]
                    failed += 1
            except Exception as e:
                a.status = AlertStatus.failed
                a.error = str(e)[:1000]
                failed += 1
                log.error("alert.dispatch.failed", alert_id=str(a.id), error=str(e))
        await db.commit()
    return {"sent": sent, "failed": failed}


def _resolve_target(channel: str, recipients: dict) -> str | None:
    """Pick the recipient/target string for the given channel."""
    from app.core.config import settings
    if channel == "email":
        return recipients.get("email") or settings.SMTP_FROM
    if channel == "telegram":
        return recipients.get("telegram_chat_id") or settings.TELEGRAM_CHAT_ID
    if channel == "discord":
        return recipients.get("discord_webhook") or settings.DISCORD_WEBHOOK_URL
    if channel == "slack":
        return recipients.get("slack_webhook") or settings.SLACK_WEBHOOK_URL
    if channel == "siem":
        return recipients.get("siem_webhook") or settings.SIEM_WEBHOOK_URL
    return None


def _build_notify_payload(a: Alert) -> dict:
    p = a.payload or {}
    return {
        "cve_id": p.get("cve_id", ""),
        "title": a.title,
        "summary": a.body,
        "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
        "cvss": p.get("cvss"),
        "kev": bool(p.get("kev")),
        "exploit_available": bool(p.get("exploit_available")),
        "references": p.get("references") or [],
        "remediation": p.get("remediation"),
        "affected_servers": [{
            "hostname": p.get("hostname"),
            "os_family": p.get("os"),
            "os_version": p.get("os_version"),
            "package": p.get("package"),
            "installed_version": p.get("installed"),
            "fixed_version": p.get("fixed_version"),
        }] if p.get("hostname") else [],
        "dashboard_url": p.get("dashboard_url", ""),
    }


@celery_app.task(name="alerts.dispatch_pending")
def dispatch_pending(limit: int = 100) -> dict:
    return asyncio.run(_dispatch_pending(limit))


@celery_app.task(name="alerts.evaluate_all_open")
def evaluate_all_open() -> dict:
    async def _run():
        async with AsyncSessionLocal() as db:
            ids = (await db.execute(
                select(Correlation.id).where(Correlation.status == CorrelationStatus.open)
            )).scalars().all()
        total = 0
        for cid in ids:
            try:
                total += await _evaluate_correlation(cid)
            except Exception as e:
                log.error("alerts.evaluate_all.error", corr_id=str(cid), error=str(e))
        return {"correlations": len(ids), "alerts_created": total}
    return asyncio.run(_run())
