"""Alert and rule schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import AlertChannel, AlertSeverity, AlertStatus


class AlertRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    min_severity: AlertSeverity = AlertSeverity.high
    require_kev: bool = False
    require_exploit: bool = False
    environments: List[str] = Field(default_factory=list)
    os_filter: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default_factory=list)
    recipients: dict = Field(default_factory=dict)
    cooldown_minutes: int = 60


class AlertRuleCreate(AlertRuleBase):
    pass


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    min_severity: Optional[AlertSeverity] = None
    require_kev: Optional[bool] = None
    require_exploit: Optional[bool] = None
    environments: Optional[List[str]] = None
    os_filter: Optional[List[str]] = None
    channels: Optional[List[str]] = None
    recipients: Optional[dict] = None
    cooldown_minutes: Optional[int] = None


class AlertRuleOut(AlertRuleBase):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    severity: AlertSeverity
    title: str
    body: Optional[str]
    channel: AlertChannel
    status: AlertStatus
    error: Optional[str]
    sent_at: Optional[datetime]
    created_at: datetime
    cve_pk: Optional[uuid.UUID]
    server_id: Optional[uuid.UUID]
