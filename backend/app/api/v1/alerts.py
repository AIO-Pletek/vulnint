"""Alert log routes."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.alert import Alert, AlertChannel, AlertStatus
from app.schemas.alert import AlertOut
from app.schemas.auth import CurrentUser
from app.schemas.common import Page
from app.workers.celery_app import celery_app

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut])
async def list_alerts(
    status_: Optional[list[AlertStatus]] = Query(None, alias="status"),
    channel: Optional[list[AlertChannel]] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_READ)),
):
    stmt = select(Alert)
    cnt = select(func.count()).select_from(Alert)
    if status_:
        stmt = stmt.where(Alert.status.in_(status_))
        cnt = cnt.where(Alert.status.in_(status_))
    if channel:
        stmt = stmt.where(Alert.channel.in_(channel))
        cnt = cnt.where(Alert.channel.in_(channel))
    stmt = stmt.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    items = list((await db.execute(stmt)).scalars())
    total = (await db.execute(cnt)).scalar_one()
    return Page[AlertOut](items=[AlertOut.model_validate(a) for a in items], total=int(total), page=page, page_size=page_size)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_READ)),
):
    a = await db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return AlertOut.model_validate(a)


@router.post("/dispatch-pending", status_code=status.HTTP_202_ACCEPTED)
async def dispatch_pending(
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_WRITE)),
):
    celery_app.send_task("alerts.dispatch_pending")
    return {"queued": True}
