"""CVE repository: upsert, query, listing."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.vulnerability import (
    AffectedProduct,
    Advisory,
    CVE,
    ExploitSource,
    Severity,
)


class CVERepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert(self, payload: dict) -> CVE:
        """Insert or update a CVE keyed on cve_id. Idempotent."""
        cve_id = payload["cve_id"]
        stmt = (
            pg_insert(CVE)
            .values(**payload)
            .on_conflict_do_update(
                index_elements=[CVE.cve_id],
                set_={
                    "title": payload.get("title"),
                    "description": payload.get("description"),
                    "severity": payload.get("severity", Severity.none),
                    "cvss_score": payload.get("cvss_score"),
                    "cvss_vector": payload.get("cvss_vector"),
                    "cvss_version": payload.get("cvss_version"),
                    "cwe": payload.get("cwe", []),
                    "references": payload.get("references", []),
                    "kev": payload.get("kev", False),
                    "exploit_available": payload.get("exploit_available", False),
                    "modified_at": payload.get("modified_at") or datetime.utcnow(),
                    "raw_data": payload.get("raw_data", {}),
                    "updated_at": func.now(),
                },
            )
            .returning(CVE)
        )
        res = await self.db.execute(stmt)
        await self.db.commit()
        return res.scalar_one()

    async def get_by_cve_id(self, cve_id: str) -> Optional[CVE]:
        res = await self.db.execute(
            select(CVE)
            .where(CVE.cve_id == cve_id)
            .options(
                selectinload(CVE.affected_products),
                selectinload(CVE.advisories),
                selectinload(CVE.exploit_sources),
            )
        )
        return res.scalar_one_or_none()

    async def replace_affected_products(self, cve_pk, products: Iterable[dict]) -> None:
        """Replace all affected products for a CVE atomically."""
        await self.db.execute(
            AffectedProduct.__table__.delete().where(AffectedProduct.cve_pk == cve_pk)
        )
        rows = [{**p, "cve_pk": cve_pk} for p in products]
        if rows:
            await self.db.execute(AffectedProduct.__table__.insert(), rows)
        await self.db.commit()

    async def add_exploit_source(self, cve_pk, source: str, external_id: str | None,
                                  url: str, published_at: datetime | None) -> None:
        stmt = (
            pg_insert(ExploitSource)
            .values(
                cve_pk=cve_pk,
                source=source,
                external_id=external_id,
                url=url,
                published_at=published_at,
            )
            .on_conflict_do_nothing(constraint="uq_exploit_unique")
        )
        await self.db.execute(stmt)
        # caller commits

    async def mark_kev(self, cve_id: str, added_at: datetime) -> None:
        await self.db.execute(
            CVE.__table__.update()
            .where(CVE.cve_id == cve_id)
            .values(kev=True, kev_added_at=added_at, exploit_available=True)
        )
        await self.db.commit()

    async def list_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        severity: Optional[Sequence[Severity]] = None,
        kev: Optional[bool] = None,
        exploit_available: Optional[bool] = None,
        min_cvss: Optional[float] = None,
        q: Optional[str] = None,
        sort: str = "published_at",
        order: str = "desc",
    ) -> Tuple[List[CVE], int]:
        stmt = select(CVE)
        count_stmt = select(func.count()).select_from(CVE)
        conds = []
        if severity:
            conds.append(CVE.severity.in_(severity))
        if kev is not None:
            conds.append(CVE.kev.is_(kev))
        if exploit_available is not None:
            conds.append(CVE.exploit_available.is_(exploit_available))
        if min_cvss is not None:
            conds.append(CVE.cvss_score >= min_cvss)
        if q:
            like = f"%{q}%"
            conds.append(or_(CVE.cve_id.ilike(like), CVE.title.ilike(like), CVE.description.ilike(like)))
        if conds:
            stmt = stmt.where(and_(*conds))
            count_stmt = count_stmt.where(and_(*conds))

        sort_col = getattr(CVE, sort, CVE.published_at)
        stmt = stmt.order_by(sort_col.desc() if order == "desc" else sort_col.asc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        items = (await self.db.execute(stmt)).scalars().all()
        total = (await self.db.execute(count_stmt)).scalar_one()
        return list(items), int(total)


class AdvisoryRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert(self, payload: dict) -> Advisory:
        stmt = (
            pg_insert(Advisory)
            .values(**payload)
            .on_conflict_do_update(
                constraint="uq_advisories_advisory_source",
                set_={
                    "title": payload.get("title"),
                    "summary": payload.get("summary"),
                    "severity": payload.get("severity", Severity.none),
                    "url": payload.get("url"),
                    "published_at": payload.get("published_at"),
                    "cve_id_ref": payload.get("cve_id_ref"),
                    "affected_packages": payload.get("affected_packages", []),
                    "raw_data": payload.get("raw_data", {}),
                    "updated_at": func.now(),
                },
            )
            .returning(Advisory)
        )
        res = await self.db.execute(stmt)
        await self.db.commit()
        return res.scalar_one()
