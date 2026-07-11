"""Repositories for servers, inventory, correlations."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional, Sequence, Tuple

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.server import InstalledPackage, Inventory, OSFamily, Server
from app.models.vulnerability import Correlation, CorrelationStatus, Severity


class ServerRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list(self, page: int = 1, page_size: int = 25,
                   os_family: Optional[OSFamily] = None,
                   q: Optional[str] = None) -> Tuple[List[Server], int]:
        stmt = select(Server).where(Server.deleted_at.is_(None))
        count = select(func.count()).select_from(Server).where(Server.deleted_at.is_(None))
        if os_family:
            stmt = stmt.where(Server.os_family == os_family)
            count = count.where(Server.os_family == os_family)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(Server.hostname.ilike(like))
            count = count.where(Server.hostname.ilike(like))
        stmt = stmt.order_by(Server.hostname.asc()).offset((page - 1) * page_size).limit(page_size)
        items = (await self.db.execute(stmt)).scalars().all()
        total = (await self.db.execute(count)).scalar_one()
        return list(items), int(total)

    async def get(self, server_id: uuid.UUID) -> Optional[Server]:
        res = await self.db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )
        return res.scalar_one_or_none()

    async def create(self, **kwargs) -> Server:
        s = Server(**kwargs)
        self.db.add(s)
        await self.db.commit()
        await self.db.refresh(s)
        return s

    async def update(self, s: Server, **fields) -> Server:
        for k, v in fields.items():
            if v is not None:
                setattr(s, k, v)
        await self.db.commit()
        await self.db.refresh(s)
        return s

    async def soft_delete(self, s: Server) -> None:
        s.deleted_at = datetime.utcnow()
        s.is_active = False
        await self.db.commit()


class InventoryRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_with_packages(
        self, server: Server, raw_payload: dict, packages: List[dict]
    ) -> Inventory:
        inv = Inventory(
            server_id=server.id,
            raw_payload=raw_payload,
            package_count=len(packages),
            collected_at=datetime.utcnow(),
        )
        self.db.add(inv)
        await self.db.flush()
        if packages:
            rows = [
                {
                    "inventory_id": inv.id,
                    "server_id": server.id,
                    "name": p["name"],
                    "version": p["version"],
                    "arch": p.get("arch"),
                    "epoch": p.get("epoch"),
                    "source": p.get("source"),
                }
                for p in packages
            ]
            await self.db.execute(InstalledPackage.__table__.insert(), rows)
        server.last_seen_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(inv)
        return inv

    async def latest_packages_for_server(self, server_id: uuid.UUID) -> List[InstalledPackage]:
        # Find the most recent inventory and return its packages
        latest_inv = await self.db.execute(
            select(Inventory.id)
            .where(Inventory.server_id == server_id)
            .order_by(Inventory.collected_at.desc())
            .limit(1)
        )
        inv_id = latest_inv.scalar_one_or_none()
        if not inv_id:
            return []
        res = await self.db.execute(
            select(InstalledPackage).where(InstalledPackage.inventory_id == inv_id)
        )
        return list(res.scalars().all())


class CorrelationRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert(
        self,
        server_id: uuid.UUID,
        cve_pk: uuid.UUID,
        package_name: str,
        installed_version: str,
        fixed_version: str | None,
        severity: Severity,
    ) -> Tuple[Correlation, bool]:
        """Returns (correlation, is_new)."""
        res = await self.db.execute(
            select(Correlation).where(
                Correlation.server_id == server_id,
                Correlation.cve_pk == cve_pk,
                Correlation.package_name == package_name,
            )
        )
        existing = res.scalar_one_or_none()
        now = datetime.utcnow()
        if existing:
            existing.installed_version = installed_version
            existing.fixed_version = fixed_version
            existing.severity = severity
            existing.last_seen_at = now
            await self.db.commit()
            return existing, False

        c = Correlation(
            server_id=server_id,
            cve_pk=cve_pk,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
            severity=severity,
            status=CorrelationStatus.open,
            first_seen_at=now,
            last_seen_at=now,
        )
        self.db.add(c)
        await self.db.commit()
        await self.db.refresh(c)
        return c, True

    async def mark_fixed(self, server_id: uuid.UUID, cve_pk: uuid.UUID,
                         package_name: str) -> None:
        res = await self.db.execute(
            select(Correlation).where(
                Correlation.server_id == server_id,
                Correlation.cve_pk == cve_pk,
                Correlation.package_name == package_name,
                Correlation.status != CorrelationStatus.fixed,
            )
        )
        c = res.scalar_one_or_none()
        if c:
            c.status = CorrelationStatus.fixed
            c.fixed_at = datetime.utcnow()
            await self.db.commit()

    async def list_open(
        self, server_id: Optional[uuid.UUID] = None,
        severity: Optional[Sequence[Severity]] = None,
        page: int = 1, page_size: int = 25,
    ) -> Tuple[List[Correlation], int]:
        conds = [Correlation.status == CorrelationStatus.open]
        if server_id:
            conds.append(Correlation.server_id == server_id)
        if severity:
            conds.append(Correlation.severity.in_(severity))
        stmt = (
            select(Correlation)
            .where(and_(*conds))
            .options(selectinload(Correlation.cve), selectinload(Correlation.server))
            .order_by(Correlation.severity.desc(), Correlation.last_seen_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        count = select(func.count()).select_from(Correlation).where(and_(*conds))
        items = (await self.db.execute(stmt)).scalars().all()
        total = (await self.db.execute(count)).scalar_one()
        return list(items), int(total)

    async def stats_summary(self) -> dict:
        result = {}
        for sev in [Severity.critical, Severity.high, Severity.medium, Severity.low]:
            res = await self.db.execute(
                select(func.count()).select_from(Correlation).where(
                    Correlation.severity == sev,
                    Correlation.status == CorrelationStatus.open,
                )
            )
            result[sev.value] = int(res.scalar_one())
        # affected unique servers
        res = await self.db.execute(
            select(func.count(func.distinct(Correlation.server_id)))
            .where(Correlation.status == CorrelationStatus.open)
        )
        result["affected_servers"] = int(res.scalar_one())
        return result
