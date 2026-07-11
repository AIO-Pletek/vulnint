"""Recompute CVE risk scores given updated context."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import AffectedProduct, CVE, Correlation
from app.utils.scoring import compute_risk_score


async def recompute_for_cve(db: AsyncSession, cve_pk) -> float:
    cve = await db.get(CVE, cve_pk)
    if not cve:
        return 0.0
    affected_q = await db.execute(
        select(func.count()).select_from(AffectedProduct).where(AffectedProduct.cve_pk == cve_pk)
    )
    affected_count = int(affected_q.scalar_one() or 0)
    prod_q = await db.execute(
        select(func.count()).select_from(Correlation).where(
            Correlation.cve_pk == cve_pk,
        )
    )
    has_prod = bool(int(prod_q.scalar_one() or 0))

    score = compute_risk_score(
        cvss=cve.cvss_score,
        kev=bool(cve.kev),
        exploit_available=bool(cve.exploit_available),
        affects_production=has_prod,
        affected_count=affected_count,
    )
    cve.risk_score = score
    await db.flush()
    return score
