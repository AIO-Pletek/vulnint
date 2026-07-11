"""Server / inventory schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.audit_finding import AuditCategory, FindingStatus
from app.models.server import Environment, OSFamily
from app.models.vulnerability import Severity


class ServerBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    os_family: OSFamily
    os_version: Optional[str] = None
    kernel: Optional[str] = None
    cpanel_version: Optional[str] = None
    environment: Environment = Environment.production
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


class ServerCreate(ServerBase):
    pass


class ServerUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_version: Optional[str] = None
    kernel: Optional[str] = None
    cpanel_version: Optional[str] = None
    environment: Optional[Environment] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    is_active: Optional[bool] = None


class ServerOut(ServerBase):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    is_active: bool
    last_seen_at: Optional[datetime]
    created_at: datetime


class ServerWithToken(ServerOut):
    api_token: str  # plaintext, returned ONCE


class InstalledPackageIn(BaseModel):
    name: str
    version: str
    arch: Optional[str] = None
    epoch: Optional[str] = None
    source: Optional[str] = None  # dpkg|rpm|kb|cpanel


class AuditFacts(BaseModel):
    """Security posture facts collected by the agent. Each section is a
    raw dict — the backend rules engine evaluates them into findings."""
    ssh: Optional[Dict[str, Any]] = None
    firewall: Optional[Dict[str, Any]] = None
    updates: Optional[Dict[str, Any]] = None
    services: Optional[Dict[str, Any]] = None
    misc: Optional[Dict[str, Any]] = None


class InventoryReport(BaseModel):
    """Payload sent by the agent."""
    hostname: str
    os_family: OSFamily
    os_version: Optional[str] = None
    kernel: Optional[str] = None
    ip_address: Optional[str] = None
    cpanel_version: Optional[str] = None
    packages: List[InstalledPackageIn] = Field(default_factory=list)
    raw_payload: dict = Field(default_factory=dict)
    audit: Optional[AuditFacts] = None  # NEW — security audit facts


class InventoryAccepted(BaseModel):
    inventory_id: uuid.UUID
    package_count: int
    correlation_job_id: Optional[str] = None


# ── Audit finding schemas ─────────────────────────────────────────────────


class AuditFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    server_id: uuid.UUID
    category: AuditCategory
    check_name: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    remediation: str
    evidence: dict
    created_at: datetime
    updated_at: datetime


class AuditFindingUpdate(BaseModel):
    status: FindingStatus


class AuditFindingsResponse(BaseModel):
    server_id: uuid.UUID
    findings: List[AuditFindingOut]
    summary: Dict[str, int]  # {"critical": N, "high": N, ...}
