"""Dashboard summary statistics."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.server import Server
from app.models.vulnerability import CVE, Correlation, CorrelationStatus, Severity
from app.schemas.auth import CurrentUser

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
async def overview(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    now = datetime.now(timezone.utc)
    last_30 = now - timedelta(days=30)

    # Server fleet
    server_total = (await db.execute(
        select(func.count()).select_from(Server).where(Server.deleted_at.is_(None))
    )).scalar_one()

    server_active = (await db.execute(
        select(func.count()).select_from(Server).where(
            Server.deleted_at.is_(None), Server.is_active.is_(True),
            Server.last_seen_at >= now - timedelta(days=2),
        )
    )).scalar_one()

    # Open correlations by severity
    sev_rows = (await db.execute(
        select(Correlation.severity, func.count())
        .where(Correlation.status == CorrelationStatus.open)
        .group_by(Correlation.severity)
    )).all()
    by_severity = {s.value: 0 for s in Severity}
    for sev, n in sev_rows:
        by_severity[sev.value] = int(n)

    # KEV-affected open correlations
    kev_open = (await db.execute(
        select(func.count())
        .select_from(Correlation)
        .join(CVE, CVE.id == Correlation.cve_pk)
        .where(Correlation.status == CorrelationStatus.open, CVE.kev.is_(True))
    )).scalar_one()

    # Total CVEs known
    cve_total = (await db.execute(select(func.count()).select_from(CVE))).scalar_one()

    # CVEs added recently
    cve_recent = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.created_at >= last_30)
    )).scalar_one()

    # Alerts last 30d
    alerts_recent = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at >= last_30)
    )).scalar_one()

    alerts_pending = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.pending)
    )).scalar_one()

    # Trend: correlations opened per day, last 30d
    trend_rows = (await db.execute(
        select(
            func.date_trunc("day", Correlation.first_seen_at).label("day"),
            func.count().label("count"),
        )
        .where(Correlation.first_seen_at >= last_30)
        .group_by("day")
        .order_by("day")
    )).all()
    trend = [{"date": row[0].isoformat() if row[0] else None, "count": int(row[1])} for row in trend_rows]

    return {
        "servers": {"total": int(server_total), "active": int(server_active)},
        "cves": {"total": int(cve_total), "added_30d": int(cve_recent)},
        "open_correlations": {
            "by_severity": by_severity,
            "kev": int(kev_open),
            "total": sum(by_severity.values()),
        },
        "alerts": {"recent_30d": int(alerts_recent), "pending": int(alerts_pending)},
        "trend_30d": trend,
    }


@router.get("/top-cves")
async def top_cves(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    rows = (await db.execute(
        select(CVE.cve_id, CVE.title, CVE.severity, CVE.cvss_score, CVE.kev, CVE.exploit_available, CVE.risk_score)
        .order_by(CVE.risk_score.desc().nullslast(), CVE.cvss_score.desc().nullslast())
        .limit(limit)
    )).all()
    return [
        {
            "cve_id": r[0], "title": r[1], "severity": r[2].value if r[2] else None,
            "cvss_score": r[3], "kev": bool(r[4]), "exploit_available": bool(r[5]),
            "risk_score": r[6],
        }
        for r in rows
    ]


@router.get("/top-affected-servers")
async def top_affected_servers(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_READ)),
):
    rows = (await db.execute(
        select(Server.id, Server.hostname, Server.os_family, Server.os_version, func.count(Correlation.id).label("vulns"))
        .join(Correlation, Correlation.server_id == Server.id)
        .where(
            Correlation.status == CorrelationStatus.open,
            Server.deleted_at.is_(None),
        )
        .group_by(Server.id)
        .order_by(func.count(Correlation.id).desc())
        .limit(limit)
    )).all()
    return [
        {"id": str(r[0]), "hostname": r[1], "os_family": r[2].value if r[2] else None, "os_version": r[3], "open_vulns": int(r[4])}
        for r in rows
    ]
