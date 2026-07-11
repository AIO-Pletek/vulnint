"""Alert rule CRUD."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.alert import AlertRule
from app.schemas.alert import AlertRuleCreate, AlertRuleOut, AlertRuleUpdate
from app.schemas.auth import CurrentUser

router = APIRouter(prefix="/alert-rules", tags=["alert-rules"])


@router.get("", response_model=list[AlertRuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_READ)),
):
    res = await db.execute(select(AlertRule).order_by(AlertRule.name))
    return [AlertRuleOut.model_validate(r) for r in res.scalars()]


@router.post("", response_model=AlertRuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_RULE_WRITE)),
):
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Rule name conflict")
    await db.refresh(rule)
    return AlertRuleOut.model_validate(rule)


@router.patch("/{rule_id}", response_model=AlertRuleOut)
async def update_rule(
    rule_id: uuid.UUID,
    body: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_RULE_WRITE)),
):
    rule = await db.get(AlertRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(rule, k, v)
    await db.commit()
    await db.refresh(rule)
    return AlertRuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.ALERT_RULE_WRITE)),
):
    rule = await db.get(AlertRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    await db.delete(rule)
    await db.commit()
