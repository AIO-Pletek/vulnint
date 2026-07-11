"""Server / inventory schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.server import Environment, OSFamily


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


class InventoryAccepted(BaseModel):
    inventory_id: uuid.UUID
    package_count: int
    correlation_job_id: Optional[str] = None
