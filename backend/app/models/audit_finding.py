"""Security audit findings produced by the agent → rules engine pipeline."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime, Enum as SAEnum, ForeignKey, Index, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDPrimaryKey
from app.models.vulnerability import Severity


class AuditCategory(str, enum.Enum):
    ssh = "ssh"
    firewall = "firewall"
    updates = "updates"
    services = "services"
    misc = "misc"


class FindingStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    fixed = "fixed"
    ignored = "ignored"


class AuditFinding(UUIDPrimaryKey, TimestampMixin, Base):
    """One security-configuration finding on a specific server.

    Findings are fully replaced on every agent inventory cycle: old findings
    for the server are deleted and replaced with the freshly evaluated set.
    This means fixed issues disappear automatically without a separate
    remediation workflow.
    """

    __tablename__ = "audit_findings"

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    category: Mapped[AuditCategory] = mapped_column(
        SAEnum(AuditCategory, name="audit_category"), nullable=False, index=True,
    )
    check_name: Mapped[str] = mapped_column(
        String(128), nullable=False,
        comment="Stable key used for upsert, e.g. ssh_permit_root_login",
    )
    severity: Mapped[Severity] = mapped_column(
        SAEnum(Severity, name="severity"), nullable=False, index=True,
    )
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status"),
        default=FindingStatus.open, index=True,
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationship for eager-loading convenience
    server = relationship("Server", back_populates="audit_findings")

    __table_args__ = (
        UniqueConstraint("server_id", "check_name", name="uq_audit_finding_server_check"),
        Index("ix_audit_findings_category_sev", "category", "severity"),
        Index("ix_audit_findings_status_sev", "status", "severity"),
    )
