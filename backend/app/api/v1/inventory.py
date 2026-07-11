"""Inventory ingestion endpoint used by Linux/Windows agents."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.agent_token import get_agent_server
from app.core.database import get_db
from app.models.server import Server
from app.repositories.audit_finding import AuditFindingRepo
from app.repositories.server import InventoryRepo
from app.schemas.server import InventoryAccepted, InventoryReport
from app.services.audit_rules import evaluate_audit_rules
from app.workers.celery_app import celery_app

router = APIRouter(prefix="/inventory", tags=["inventory"])


@router.post("", response_model=InventoryAccepted, status_code=status.HTTP_202_ACCEPTED)
async def ingest_inventory(
    body: InventoryReport,
    server: Server = Depends(get_agent_server),
    db: AsyncSession = Depends(get_db),
):
    # Update server fingerprint
    if body.os_family:
        server.os_family = body.os_family
    if body.os_version:
        server.os_version = body.os_version
    if body.kernel:
        server.kernel = body.kernel
    if body.cpanel_version is not None:
        server.cpanel_version = body.cpanel_version
    if body.hostname and body.hostname != server.hostname:
        # Trust agent hostname only on first contact
        if not server.last_seen_at:
            server.hostname = body.hostname
    server.last_seen_at = datetime.now(timezone.utc)

    repo = InventoryRepo(db)
    inv = await repo.create_with_packages(
        server=server,
        raw_payload=body.raw_payload or {},
        packages=[p.model_dump() for p in body.packages],
    )
    await db.commit()

    # Process security audit facts → findings (if agent sent them)
    if body.audit:
        try:
            findings = evaluate_audit_rules(server, body.audit.model_dump())
            if findings:
                await AuditFindingRepo(db).upsert_findings(server.id, findings)
        except Exception:
            # Audit evaluation must never fail the overall inventory ingest.
            pass

    # Trigger correlation in background
    res = celery_app.send_task("correlation.run_for_server", args=[str(server.id)])

    return InventoryAccepted(
        inventory_id=inv.id,
        package_count=inv.package_count,
        correlation_job_id=res.id if res else None,
    )
