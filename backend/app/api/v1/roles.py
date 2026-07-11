"""Roles & permissions catalog."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.user import Permission, Role
from app.schemas.auth import CurrentUser, PermissionOut, RoleOut

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("", response_model=list[RoleOut])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_READ)),
):
    res = await db.execute(select(Role).order_by(Role.name))
    return [RoleOut.model_validate(r) for r in res.scalars()]


@router.get("/{role_id}/permissions", response_model=list[PermissionOut])
async def get_role_permissions(
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_READ)),
):
    res = await db.execute(
        select(Role).where(Role.id == role_id).options(selectinload(Role.permissions))
    )
    role = res.scalar_one_or_none()
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return [PermissionOut.model_validate(p) for p in role.permissions]


@router.get("/-/permissions", response_model=list[PermissionOut])
async def list_permissions(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_READ)),
):
    res = await db.execute(select(Permission).order_by(Permission.code))
    return [PermissionOut.model_validate(p) for p in res.scalars()]
