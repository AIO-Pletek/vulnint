"""Server CRUD: list, create (returns plaintext token), update, regen token, delete."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.agent_token import generate_agent_token
from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.server import OSFamily
from app.repositories.server import ServerRepo
from app.schemas.auth import CurrentUser
from app.schemas.common import Page
from app.schemas.server import ServerCreate, ServerOut, ServerUpdate, ServerWithToken

router = APIRouter(prefix="/servers", tags=["servers"])


def _to_out(s) -> ServerOut:
    return ServerOut(
        id=s.id,
        hostname=s.hostname,
        ip_address=s.ip_address,
        environment=s.environment,
        os_family=s.os_family,
        os_version=s.os_version,
        kernel=s.kernel,
        cpanel_version=s.cpanel_version,
        tags=s.tags or [],
        notes=s.notes,
        is_active=s.is_active,
        last_seen_at=s.last_seen_at,
        created_at=s.created_at,
    )


@router.get("", response_model=Page[ServerOut])
async def list_servers(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    os_family: Optional[OSFamily] = None,
    q: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_READ)),
):
    repo = ServerRepo(db)
    items, total = await repo.list(page=page, page_size=page_size, os_family=os_family, q=q)
    return Page[ServerOut](
        items=[_to_out(s) for s in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ServerWithToken, status_code=status.HTTP_201_CREATED)
async def create_server(
    body: ServerCreate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_WRITE)),
):
    plaintext, digest = generate_agent_token()
    repo = ServerRepo(db)
    s = await repo.create(
        hostname=body.hostname,
        ip_address=body.ip_address,
        environment=body.environment,
        os_family=body.os_family,
        os_version=body.os_version,
        kernel=body.kernel,
        cpanel_version=body.cpanel_version,
        tags=body.tags or [],
        notes=body.notes,
        api_token_hash=digest,
        is_active=True,
    )
    out = _to_out(s).model_dump()
    return ServerWithToken(**out, api_token=plaintext)


@router.get("/{server_id}", response_model=ServerOut)
async def get_server(
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_READ)),
):
    repo = ServerRepo(db)
    s = await repo.get(server_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return _to_out(s)


@router.patch("/{server_id}", response_model=ServerOut)
async def update_server(
    server_id: uuid.UUID,
    body: ServerUpdate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_WRITE)),
):
    repo = ServerRepo(db)
    s = await repo.get(server_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    s = await repo.update(s, **body.model_dump(exclude_unset=True))
    return _to_out(s)


@router.post("/{server_id}/regen-token", response_model=ServerWithToken)
async def regen_token(
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_WRITE)),
):
    repo = ServerRepo(db)
    s = await repo.get(server_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    plaintext, digest = generate_agent_token()
    s.api_token_hash = digest
    await db.commit()
    await db.refresh(s)
    out = _to_out(s).model_dump()
    return ServerWithToken(**out, api_token=plaintext)


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_server(
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_DELETE)),
):
    repo = ServerRepo(db)
    s = await repo.get(server_id)
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    await repo.soft_delete(s)
