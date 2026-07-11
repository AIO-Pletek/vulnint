"""Multi-channel alert dispatcher.

Channels:
  - email   : SMTP via aiosmtplib (HTML + plaintext multipart)
  - telegram: Bot API sendMessage
  - discord : webhook with rich embed
  - slack   : webhook with block kit
  - siem    : generic JSON webhook (for splunk/elastic/wazuh/etc)
"""
from __future__ import annotations

import json
from email.message import EmailMessage
from typing import Any

import aiosmtplib
import httpx
import structlog

from app.core.config import settings
from app.services.email_template import render_alert_email

log = structlog.get_logger(__name__)


_SEV_COLOR_HEX = {
    "critical": 0x991B1B,
    "high":     0xC2410C,
    "medium":   0xCA8A04,
    "low":      0x2563EB,
    "none":     0x4B5563,
}


async def _send_email(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not (settings.SMTP_HOST and settings.SMTP_FROM):
        return {"ok": False, "error": "smtp_not_configured"}

    subject, html, text = render_alert_email(payload)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = target
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME or None,
            password=settings.SMTP_PASSWORD or None,
            start_tls=settings.SMTP_TLS,
            timeout=30,
        )
        return {"ok": True}
    except Exception as e:
        log.error("smtp_send_failed", err=str(e))
        return {"ok": False, "error": str(e)}


async def _send_telegram(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    """target is the chat_id; bot token comes from settings."""
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        return {"ok": False, "error": "telegram_not_configured"}

    sev = (payload.get("severity") or "none").upper()
    cvss = f" · CVSS {payload['cvss']:.1f}" if payload.get("cvss") else ""
    kev = " · 🔥 KEV" if payload.get("kev") else ""
    text = (
        f"*VulnInt Alert* — `{payload.get('cve_id')}`\n"
        f"*{sev}*{cvss}{kev}\n\n"
        f"_{payload.get('title') or 'Vulnerability detected'}_\n\n"
    )
    if payload.get("affected_servers"):
        text += "*Affected:* "
        text += ", ".join(s["hostname"] for s in payload["affected_servers"][:5])
        if len(payload["affected_servers"]) > 5:
            text += f" (+{len(payload['affected_servers']) - 5} more)"
        text += "\n\n"
    text += f"[Open dashboard]({payload.get('dashboard_url')})"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = {
        "chat_id": target,
        "text": text[:4000],
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(url, json=body)
            r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        log.error("telegram_send_failed", err=str(e))
        return {"ok": False, "error": str(e)}


async def _send_discord(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    """target is the webhook URL."""
    sev = (payload.get("severity") or "none").lower()
    fields = []
    if payload.get("cvss"):
        fields.append({"name": "CVSS", "value": f"{payload['cvss']:.1f}", "inline": True})
    fields.append({"name": "Severity", "value": sev.upper(), "inline": True})
    fields.append({"name": "KEV", "value": "Yes" if payload.get("kev") else "No", "inline": True})
    if payload.get("affected_servers"):
        srv = "\n".join(
            f"• `{s['hostname']}` — {s.get('package','')} {s.get('installed_version','')}"
            for s in payload["affected_servers"][:8]
        )
        fields.append({"name": f"Affected ({len(payload['affected_servers'])})", "value": srv[:1024], "inline": False})

    embed = {
        "title": f"{payload.get('cve_id')} — {payload.get('title') or 'Vulnerability detected'}"[:256],
        "url": payload.get("dashboard_url"),
        "description": (payload.get("summary") or "")[:2048],
        "color": _SEV_COLOR_HEX.get(sev, _SEV_COLOR_HEX["none"]),
        "fields": fields,
        "footer": {"text": "VulnInt"},
    }
    body = {"username": "VulnInt", "embeds": [embed]}
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(target, json=body)
            r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        log.error("discord_send_failed", err=str(e))
        return {"ok": False, "error": str(e)}


async def _send_slack(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    """target is the incoming webhook URL."""
    sev = (payload.get("severity") or "none").upper()
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"VulnInt Alert: {payload.get('cve_id')}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
                {"type": "mrkdwn", "text": f"*CVSS*\n{payload.get('cvss') or '—'}"},
                {"type": "mrkdwn", "text": f"*KEV*\n{'Yes' if payload.get('kev') else 'No'}"},
                {"type": "mrkdwn", "text": f"*Exploit*\n{'Available' if payload.get('exploit_available') else 'Unknown'}"},
            ],
        },
    ]
    if payload.get("title"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{payload['title']}*"}})
    if payload.get("summary"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": payload["summary"][:2900]}})
    if payload.get("affected_servers"):
        text = "\n".join(
            f"• `{s['hostname']}` — {s.get('package','')} `{s.get('installed_version','')}` → fix `{s.get('fixed_version') or '?'}`"
            for s in payload["affected_servers"][:10]
        )
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Affected servers ({len(payload['affected_servers'])})*\n{text}"}})
    blocks.append({
        "type": "actions",
        "elements": [{
            "type": "button",
            "text": {"type": "plain_text", "text": "Open Dashboard"},
            "url": payload.get("dashboard_url"),
            "style": "primary",
        }],
    })

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(target, json={"blocks": blocks})
            r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        log.error("slack_send_failed", err=str(e))
        return {"ok": False, "error": str(e)}


async def _send_siem(target: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Generic JSON webhook for SIEM ingest."""
    body = {
        "event_type": "vulnerability_alert",
        "source": "vulnint",
        **payload,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(target, json=body, headers={"Content-Type": "application/json"})
            r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        log.error("siem_send_failed", err=str(e))
        return {"ok": False, "error": str(e)}


_DISPATCH = {
    "email":    _send_email,
    "telegram": _send_telegram,
    "discord":  _send_discord,
    "slack":    _send_slack,
    "siem":     _send_siem,
}


async def dispatch_alert(channel: str, target: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a single alert to a single channel target. Returns delivery result."""
    fn = _DISPATCH.get(channel.lower())
    if not fn:
        return {"ok": False, "error": f"unknown_channel:{channel}"}
    return await fn(target, payload)
