"""Audit log read endpoint (admins only)."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.audit import AuditLog
from app.schemas.auth import CurrentUser
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit(
    actor_id: Optional[uuid.UUID] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.AUDIT_READ)),
):
    stmt = select(AuditLog)
    cnt = select(func.count()).select_from(AuditLog)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
        cnt = cnt.where(AuditLog.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
        cnt = cnt.where(AuditLog.action == action)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
        cnt = cnt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
        cnt = cnt.where(AuditLog.resource_id == resource_id)
    stmt = stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = list((await db.execute(stmt)).scalars())
    total = (await db.execute(cnt)).scalar_one()
    items = [
        {
            "id": str(r.id),
            "actor_id": str(r.actor_id) if r.actor_id else None,
            "actor_email": r.actor_email,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "details": r.details,
            "created_at": r.created_at,
        }
        for r in rows
    ]
    return {"items": items, "total": int(total), "page": page, "page_size": page_size}
