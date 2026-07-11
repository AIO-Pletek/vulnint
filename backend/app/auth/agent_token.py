"""Agent token authentication. Each server gets a unique long-lived bearer token."""
from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.server import Server


def generate_agent_token() -> Tuple[str, str]:
    """Returns (plaintext_token, sha256_hex)."""
    token = "vai_" + secrets.token_urlsafe(40)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def get_agent_server(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
    db: AsyncSession = Depends(get_db),
) -> Server:
    if not x_agent_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing X-Agent-Token header")
    digest = hash_token(x_agent_token)
    res = await db.execute(
        select(Server).where(Server.api_token_hash == digest, Server.is_active.is_(True))
    )
    server = res.scalar_one_or_none()
    if not server:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")
    return server
