"""User management routes (admin)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.core.security import hash_password
from app.models.user import Role, User, UserRole
from app.schemas.auth import CurrentUser, RoleOut, UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


def _to_out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        full_name=u.full_name,
        is_active=u.is_active,
        is_superuser=u.is_superuser,
        is_verified=u.is_verified,
        created_at=u.created_at,
        roles=[RoleOut(id=r.id, name=r.name, description=r.description) for r in u.roles],
    )


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_READ)),
):
    res = await db.execute(
        select(User).where(User.deleted_at.is_(None)).options(selectinload(User.roles)).order_by(User.email)
    )
    return [_to_out(u) for u in res.scalars()]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_WRITE)),
):
    existing = await db.execute(select(User).where(User.email == body.email.lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(
        email=body.email.lower(),
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        is_active=body.is_active,
        is_superuser=body.is_superuser,
    )
    db.add(user)
    await db.flush()

    if body.role_ids:
        roles_q = await db.execute(select(Role).where(Role.id.in_(body.role_ids)))
        for r in roles_q.scalars():
            db.add(UserRole(user_id=user.id, role_id=r.id))
        await db.flush()

    await db.refresh(user, attribute_names=["roles"])
    await db.commit()
    return _to_out(user)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_WRITE)),
):
    res = await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None)).options(selectinload(User.roles))
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password:
        user.hashed_password = hash_password(body.password)
    if body.role_ids is not None:
        await db.execute(sa_delete(UserRole).where(UserRole.user_id == user.id))
        roles_q = await db.execute(select(Role).where(Role.id.in_(body.role_ids)))
        for r in roles_q.scalars():
            db.add(UserRole(user_id=user.id, role_id=r.id))

    await db.flush()
    await db.refresh(user, attribute_names=["roles"])
    await db.commit()
    return _to_out(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.USER_WRITE)),
):
    res = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    user.deleted_at = datetime.now(timezone.utc)
    user.is_active = False
    await db.commit()
