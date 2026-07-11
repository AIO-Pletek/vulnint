"""CVE search and detail endpoints."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.vulnerability import AffectedProduct, Advisory, CVE, ExploitSource
from app.repositories.cve import CVERepo
from app.schemas.auth import CurrentUser
from app.schemas.vulnerability import AdvisoryOut, AffectedProductOut, CVEDetail, CVEOut
from app.services.opensearch_search import search_cves as os_search

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("")
async def search(
    q: Optional[str] = None,
    severity: Optional[list[str]] = Query(None),
    os_family: Optional[list[str]] = Query(None),
    vendor: Optional[list[str]] = Query(None),
    kev: Optional[bool] = None,
    exploit_available: Optional[bool] = None,
    min_cvss: Optional[float] = None,
    sort: str = "modified_at",
    order: str = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    return os_search(
        q=q,
        severity=severity,
        os_families=os_family,
        vendors=vendor,
        kev=kev,
        exploit_available=exploit_available,
        min_cvss=min_cvss,
        sort=sort,
        order=order,
        page=page,
        size=page_size,
    )


@router.get("/{cve_id}", response_model=CVEDetail)
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    res = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = res.scalar_one_or_none()
    if not cve:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    ap_res = await db.execute(select(AffectedProduct).where(AffectedProduct.cve_pk == cve.id))
    affected = list(ap_res.scalars())

    detail = CVEDetail.model_validate(cve)
    detail.affected_products = [AffectedProductOut.model_validate(a) for a in affected]
    return detail


@router.get("/{cve_id}/advisories", response_model=list[AdvisoryOut])
async def cve_advisories(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    cve_q = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = cve_q.scalar_one_or_none()
    if not cve:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    res = await db.execute(select(Advisory).where(Advisory.cve_id_ref == cve.id).order_by(Advisory.published_at.desc()))
    return [AdvisoryOut.model_validate(a) for a in res.scalars()]


@router.get("/{cve_id}/exploits")
async def cve_exploits(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.CVE_READ)),
):
    cve_q = await db.execute(select(CVE).where(CVE.cve_id == cve_id.upper()))
    cve = cve_q.scalar_one_or_none()
    if not cve:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    res = await db.execute(select(ExploitSource).where(ExploitSource.cve_pk == cve.id))
    return [
        {"source": e.source, "external_id": e.external_id, "url": e.url, "published_at": e.published_at}
        for e in res.scalars()
    ]
