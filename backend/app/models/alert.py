"""Alert and alert rule models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDPrimaryKey


class AlertChannel(str, enum.Enum):
    email = "email"
    telegram = "telegram"
    discord = "discord"
    slack = "slack"
    siem = "siem"


class AlertStatus(str, enum.Enum):
    pending = "pending"
    sent = "sent"
    failed = "failed"
    suppressed = "suppressed"


class AlertSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertRule(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "alert_rules"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), default=AlertSeverity.high
    )
    require_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    require_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    environments: Mapped[list] = mapped_column(ARRAY(String(32)), default=list, server_default="{}")
    os_filter: Mapped[list] = mapped_column(ARRAY(String(32)), default=list, server_default="{}")
    channels: Mapped[list] = mapped_column(ARRAY(String(32)), default=list, server_default="{}")
    recipients: Mapped[dict] = mapped_column(JSONB, default=dict)  # per-channel recipient config
    cooldown_minutes: Mapped[int] = mapped_column(default=60)


class Alert(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "alerts"

    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_rules.id", ondelete="SET NULL"), index=True
    )
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("correlations.id", ondelete="CASCADE"), index=True
    )
    cve_pk: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cves.id", ondelete="SET NULL"), index=True
    )
    server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("servers.id", ondelete="SET NULL"), index=True
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    channel: Mapped[AlertChannel] = mapped_column(Enum(AlertChannel, name="alert_channel"), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"), default=AlertStatus.pending, index=True
    )
    error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)

    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
    )
