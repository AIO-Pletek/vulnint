"""Correlations list & status updates."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.server import Server
from app.models.vulnerability import CVE, Correlation, CorrelationStatus, Severity
from app.schemas.auth import CurrentUser
from app.schemas.common import Page
from app.schemas.vulnerability import CorrelationDetail, CorrelationStatusUpdate
from app.services.audit import write_audit

router = APIRouter(prefix="/correlations", tags=["correlations"])


@router.get("", response_model=Page[CorrelationDetail])
async def list_correlations(
    server_id: Optional[uuid.UUID] = None,
    cve_id: Optional[str] = None,
    severity: Optional[list[Severity]] = Query(None),
    status_: Optional[list[CorrelationStatus]] = Query(None, alias="status"),
    kev: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CORRELATION_READ)),
):
    stmt = (
        select(Correlation, CVE.cve_id, CVE.cvss_score, CVE.kev, CVE.exploit_available, Server.hostname)
        .join(CVE, CVE.id == Correlation.cve_pk)
        .join(Server, Server.id == Correlation.server_id)
    )
    cnt = select(func.count()).select_from(Correlation)
    if server_id:
        stmt = stmt.where(Correlation.server_id == server_id)
        cnt = cnt.where(Correlation.server_id == server_id)
    if cve_id:
        stmt = stmt.where(CVE.cve_id == cve_id.upper())
        cnt = cnt.join(CVE, CVE.id == Correlation.cve_pk).where(CVE.cve_id == cve_id.upper())
    if severity:
        stmt = stmt.where(Correlation.severity.in_(severity))
        cnt = cnt.where(Correlation.severity.in_(severity))
    if status_:
        stmt = stmt.where(Correlation.status.in_(status_))
        cnt = cnt.where(Correlation.status.in_(status_))
    if kev is not None:
        stmt = stmt.where(CVE.kev.is_(kev))
        # cnt may not have CVE join; rebuild
        cnt = (
            select(func.count())
            .select_from(Correlation)
            .join(CVE, CVE.id == Correlation.cve_pk)
            .where(CVE.kev.is_(kev))
        )

    stmt = stmt.order_by(Correlation.severity.desc(), Correlation.last_seen_at.desc().nullslast()).offset(
        (page - 1) * page_size
    ).limit(page_size)

    rows = (await db.execute(stmt)).all()
    total = (await db.execute(cnt)).scalar_one()

    items: list[CorrelationDetail] = []
    for c, cve_id_str, cvss, kev_flag, exploit, hostname in rows:
        items.append(
            CorrelationDetail(
                id=c.id,
                server_id=c.server_id,
                cve_pk=c.cve_pk,
                package_name=c.package_name,
                installed_version=c.installed_version,
                fixed_version=c.fixed_version,
                severity=c.severity,
                status=c.status,
                first_seen_at=c.first_seen_at,
                last_seen_at=c.last_seen_at,
                fixed_at=c.fixed_at,
                notes=c.notes,
                cve_id=cve_id_str,
                hostname=hostname,
                cvss_score=cvss,
                kev=bool(kev_flag),
                exploit_available=bool(exploit),
            )
        )
    return Page[CorrelationDetail](items=items, total=int(total), page=page, page_size=page_size)


@router.patch("/{correlation_id}", response_model=CorrelationDetail)
async def update_status(
    correlation_id: uuid.UUID,
    body: CorrelationStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions(Perm.CORRELATION_WRITE)),
):
    res = await db.execute(select(Correlation).where(Correlation.id == correlation_id))
    c = res.scalar_one_or_none()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    prev = c.status.value
    c.status = body.status
    if body.notes is not None:
        c.notes = body.notes
    if body.status == CorrelationStatus.fixed and not c.fixed_at:
        c.fixed_at = datetime.now(timezone.utc)
    await write_audit(
        db,
        actor_user_id=user.id,
        action="correlation.status_change",
        resource_type="correlation",
        resource_id=str(c.id),
        metadata={"from": prev, "to": c.status.value, "notes": body.notes},
    )
    await db.commit()
    await db.refresh(c)

    cve = await db.get(CVE, c.cve_pk)
    server = await db.get(Server, c.server_id)
    return CorrelationDetail(
        id=c.id,
        server_id=c.server_id,
        cve_pk=c.cve_pk,
        package_name=c.package_name,
        installed_version=c.installed_version,
        fixed_version=c.fixed_version,
        severity=c.severity,
        status=c.status,
        first_seen_at=c.first_seen_at,
        last_seen_at=c.last_seen_at,
        fixed_at=c.fixed_at,
        notes=c.notes,
        cve_id=cve.cve_id if cve else "",
        hostname=server.hostname if server else None,
        cvss_score=cve.cvss_score if cve else None,
        kev=bool(cve.kev) if cve else False,
        exploit_available=bool(cve.exploit_available) if cve else False,
    )
