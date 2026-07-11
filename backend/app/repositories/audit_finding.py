"""AuditFinding data-access repository."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_finding import AuditFinding, FindingStatus


class AuditFindingRepo:
    """Replace-based lifecycle: each agent inventory deletes all findings for
    the server and inserts freshly evaluated ones.  This means a configuration
    fix is reflected as soon as the next agent run completes."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert_findings(
        self, server_id: uuid.UUID, findings: List[dict]
    ) -> List[AuditFinding]:
        """Replace all findings for *server_id* with *findings*."""
        # Preserve status for checks that existed before and are still open
        old_rows = (
            await self.db.execute(
                select(AuditFinding).where(AuditFinding.server_id == server_id)
            )
        ).scalars().all()
        old_by_check: dict[str, AuditFinding] = {
            r.check_name: r for r in old_rows
        }

        await self.db.execute(
            delete(AuditFinding).where(AuditFinding.server_id == server_id)
        )

        new_rows: List[AuditFinding] = []
        for f in findings:
            check = f["check_name"]
            old = old_by_check.get(check)
            status = (
                old.status
                if old and old.status != FindingStatus.fixed
                else FindingStatus.open
            )
            row = AuditFinding(
                server_id=server_id,
                check_name=check,
                category=f["category"],
                severity=f["severity"],
                status=status,
                title=f["title"],
                description=f.get("description", ""),
                remediation=f.get("remediation", ""),
                evidence=f.get("evidence", {}),
            )
            self.db.add(row)
            new_rows.append(row)

        await self.db.commit()
        return new_rows

    async def get_for_server(
        self, server_id: uuid.UUID
    ) -> List[AuditFinding]:
        res = await self.db.execute(
            select(AuditFinding)
            .where(AuditFinding.server_id == server_id)
            .order_by(AuditFinding.severity.desc(), AuditFinding.category.asc())
        )
        return list(res.scalars().all())

    async def update_status(
        self, finding_id: uuid.UUID, new_status: str
    ) -> Optional[AuditFinding]:
        row = await self.db.get(AuditFinding, finding_id)
        if not row:
            return None
        try:
            row.status = FindingStatus(new_status)
        except ValueError:
            return None
        row.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(row)
        return row
