"""Authentication routes: login, refresh, current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import get_current_user, get_request_metadata
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token, verify_password
from app.models.user import User
from app.schemas.auth import CurrentUser, LoginRequest, RefreshRequest, TokenPair
from app.services.audit import write_audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _make_pair(sub: str) -> TokenPair:
    return TokenPair(
        access_token=create_access_token(sub),
        refresh_token=create_refresh_token(sub),
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    meta: dict = Depends(get_request_metadata),
):
    res = await db.execute(
        select(User).where(User.email == body.email.lower(), User.deleted_at.is_(None))
    )
    user = res.scalar_one_or_none()
    if not user or not user.is_active or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    pair = _make_pair(str(user.id))
    await write_audit(
        db, actor_user_id=user.id, actor_email=user.email,
        action="auth.login", resource_type="user", resource_id=str(user.id), **meta,
    )
    await db.commit()
    return pair


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest):
    try:
        payload = decode_token(body.refresh_token)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(e))
    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return _make_pair(sub)


@router.get("/me", response_model=CurrentUser)
async def me(user: CurrentUser = Depends(get_current_user)):
    return user
