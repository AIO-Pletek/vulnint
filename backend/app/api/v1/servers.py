"""Server CRUD: list, create (returns plaintext token), update, regen token, delete."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.agent_token import generate_agent_token
from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.core.database import get_db
from app.models.server import OSFamily
from app.repositories.audit_finding import AuditFindingRepo
from app.repositories.server import ServerRepo
from app.schemas.auth import CurrentUser
from app.schemas.common import Page
from app.schemas.server import (
    AuditFindingOut,
    AuditFindingUpdate,
    AuditFindingsResponse,
    ServerCreate,
    ServerOut,
    ServerUpdate,
    ServerWithToken,
)

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


# ── Audit findings ─────────────────────────────────────────────────────────


@router.get("/{server_id}/findings", response_model=AuditFindingsResponse)
async def get_server_findings(
    server_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_READ)),
):
    """Return all security audit findings for a server, grouped by category."""
    # Verify server exists
    srv_repo = ServerRepo(db)
    srv = await srv_repo.get(server_id)
    if not srv:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    repo = AuditFindingRepo(db)
    findings = await repo.get_for_server(server_id)

    sev_order = ["critical", "high", "medium", "low", "none"]
    summary: dict[str, int] = {s: 0 for s in sev_order}
    for f in findings:
        key = f.severity.value
        summary[key] = summary.get(key, 0) + 1
    summary = {k: v for k, v in summary.items() if v > 0 or k in ("critical", "high")}

    return AuditFindingsResponse(
        server_id=server_id,
        findings=[AuditFindingOut.model_validate(f) for f in findings],
        summary=summary,
    )


@router.patch("/findings/{finding_id}", response_model=AuditFindingOut)
async def update_finding_status(
    finding_id: uuid.UUID,
    body: AuditFindingUpdate,
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_WRITE)),
):
    """Acknowledge or ignore a security audit finding."""
    repo = AuditFindingRepo(db)
    finding = await repo.update_status(finding_id, body.status.value)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return AuditFindingOut.model_validate(finding)


# ── Report generation ──────────────────────────────────────────────────────

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"
_jinja = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)


def _render_audit_report(server, findings: list, summary: dict) -> str:
    categories = ["ssh", "firewall", "updates", "services", "misc"]
    grouped = []
    for cat in categories:
        items = [f for f in findings if f.category.value == cat]
        grouped.append({"name": cat, "findings": items})

    tpl = _jinja.get_template("audit_report.html.j2")
    return tpl.render(
        hostname=server.hostname,
        os_family=server.os_family.value if server.os_family else "?",
        os_version=server.os_version or "",
        kernel=server.kernel or "",
        ip_address=server.ip_address or "",
        environment=server.environment.value if server.environment else "production",
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        categories=grouped,
        total=len(findings),
    )


@router.get("/{server_id}/report", response_class=HTMLResponse)
async def get_server_report(
    server_id: uuid.UUID,
    download: bool = Query(False, description="Force download as file"),
    db: AsyncSession = Depends(get_db),
    _: CurrentUser = Depends(require_permissions(Perm.SERVER_READ)),
):
    """Generate an HTML security audit report. Add ?download=1 to force download."""
    srv_repo = ServerRepo(db)
    srv = await srv_repo.get(server_id)
    if not srv:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    repo = AuditFindingRepo(db)
    findings = await repo.get_for_server(server_id)

    sev_order = ["critical", "high", "medium", "low", "none"]
    summary: dict[str, int] = {s: 0 for s in sev_order}
    for f in findings:
        key = f.severity.value
        summary[key] = summary.get(key, 0) + 1

    html = _render_audit_report(srv, findings, summary)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="vulnint-audit-{srv.hostname}.html"'
    return HTMLResponse(content=html, headers=headers)
