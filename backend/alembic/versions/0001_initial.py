"""initial schema

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00

This migration uses SQLAlchemy's metadata create_all under the alembic-managed
connection. All ORM-defined tables, enums, indexes, and constraints are created
in one shot. This avoids drift between models and migration when the model is
authoritative.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Import all models so their tables register on Base.metadata
from app.core.database import Base
from app.models import audit, alert, server, user, vulnerability  # noqa: F401

revision: str = "0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    # Required PG extensions
    bind.execute(sa.text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'))
    bind.execute(sa.text('CREATE EXTENSION IF NOT EXISTS "pg_trgm";'))
    # Create everything declared on the ORM metadata
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
    # Drop enum types created implicitly by SQLAlchemy
    for enum_name in ("severity", "correlation_status", "alert_severity",
                      "alert_status", "alert_channel", "os_family", "environment"):
        bind.execute(sa.text(f'DROP TYPE IF EXISTS {enum_name} CASCADE;'))
