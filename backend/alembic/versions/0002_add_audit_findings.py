"""add audit_findings table

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-11 00:00:00

Adds the audit_findings table for storing agent-collected security posture
findings. Each row is one configuration issue on one server, keyed by the
stable check_name (e.g. ssh_permit_root_login). Findings are fully replaced
on each agent inventory cycle.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_findings",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("server_id", sa.Uuid(), nullable=False),
        sa.Column(
            "category",
            sa.Enum("ssh", "firewall", "updates", "services", "misc", name="audit_category"),
            nullable=False,
        ),
        sa.Column(
            "check_name",
            sa.String(128),
            nullable=False,
            comment="Stable key used for upsert, e.g. ssh_permit_root_login",
        ),
        sa.Column(
            "severity",
            sa.Enum("none", "low", "medium", "high", "critical", name="severity",
                    create_type=False),  # severity type already exists (created in 0001)
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("open", "acknowledged", "fixed", "ignored", name="finding_status"),
            nullable=False,
            server_default="open",
        ),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
        ),
        # Foreign key
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            ondelete="CASCADE",
            name="fk_audit_findings_server_id",
        ),
        # Unique constraint
        sa.UniqueConstraint(
            "server_id", "check_name",
            name="uq_audit_finding_server_check",
        ),
        # Indexes
        sa.Index("ix_audit_findings_server_id", "server_id"),
        sa.Index("ix_audit_findings_category", "category"),
        sa.Index("ix_audit_findings_category_sev", "category", "severity"),
        sa.Index("ix_audit_findings_status", "status"),
        sa.Index("ix_audit_findings_status_sev", "status", "severity"),
        sa.Index("ix_audit_findings_severity", "severity"),
    )


def downgrade() -> None:
    op.drop_table("audit_findings")
    # Drop the enums that were created for this table
    sa.Enum(name="audit_category").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="finding_status").drop(op.get_bind(), checkfirst=True)
