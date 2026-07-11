"""FastAPI auth dependencies."""
from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User
from app.schemas.auth import CurrentUser

bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    try:
        payload = decode_token(creds.credentials)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(e))

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        user_id = uuid.UUID(sub)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid subject")

    res = await db.execute(
        select(User).where(User.id == user_id, User.deleted_at.is_(None))
        .options(selectinload(User.roles))
    )
    user = res.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User inactive or not found")

    perms: set[str] = set()
    for r in user.roles:
        for p in r.permissions:
            perms.add(p.code)

    return CurrentUser(
        id=user.id,
        email=user.email,
        is_superuser=user.is_superuser,
        permissions=sorted(perms),
    )


def require_permissions(*required: str) -> Callable:
    """FastAPI dependency factory for permission checks."""

    async def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.is_superuser:
            return user
        missing = [p for p in required if p not in user.permissions]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: {', '.join(missing)}",
            )
        return user

    return checker


async def get_request_metadata(request: Request) -> dict:
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }
