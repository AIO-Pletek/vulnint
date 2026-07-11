"""Server inventory models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import List

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey, Index, String, Text, UniqueConstraint, func
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDPrimaryKey


class OSFamily(str, enum.Enum):
    ubuntu = "ubuntu"
    debian = "debian"
    almalinux = "almalinux"
    rocky = "rocky"
    cloudlinux = "cloudlinux"
    windows = "windows"
    other = "other"


class Environment(str, enum.Enum):
    production = "production"
    staging = "staging"
    development = "development"
    other = "other"


class Server(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "servers"

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    os_family: Mapped[OSFamily] = mapped_column(Enum(OSFamily, name="os_family"), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(64))
    kernel: Mapped[str | None] = mapped_column(String(128))
    cpanel_version: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="environment"), default=Environment.production
    )
    tags: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    api_token_hash: Mapped[str | None] = mapped_column(String(255), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)

    inventories: Mapped[List["Inventory"]] = relationship(back_populates="server", cascade="all,delete")
    correlations = relationship("Correlation", back_populates="server", cascade="all,delete")

    __table_args__ = (
        UniqueConstraint("hostname", "ip_address", name="uq_servers_hostname_ip"),
        Index("ix_servers_os_family", "os_family"),
    )


class Inventory(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "inventories"

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    raw_payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    package_count: Mapped[int] = mapped_column(default=0)

    server: Mapped[Server] = relationship(back_populates="inventories")
    packages: Mapped[List["InstalledPackage"]] = relationship(
        back_populates="inventory", cascade="all,delete-orphan"
    )


class InstalledPackage(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "installed_packages"

    inventory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("inventories.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    arch: Mapped[str | None] = mapped_column(String(32))
    epoch: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str | None] = mapped_column(String(64))  # dpkg/rpm/kb/cpanel

    inventory: Mapped[Inventory] = relationship(back_populates="packages")

    __table_args__ = (
        Index("ix_installed_packages_name_version", "name", "version"),
    )
