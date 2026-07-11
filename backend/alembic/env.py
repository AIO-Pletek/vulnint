"""Alembic environment - synchronous, reads URL from settings.SYNC_DATABASE_URL."""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

# Ensure the project root (which contains the `app` package) is on sys.path
# regardless of how alembic was invoked. Without this, `alembic upgrade head`
# fails with ModuleNotFoundError: No module named 'app' when the CWD isn't
# the backend dir.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.core.database import Base
# Import all models so Alembic autogenerate sees them
from app.models import audit, alert, server, user, vulnerability  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", settings.SYNC_DATABASE_URL)
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.SYNC_DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = settings.SYNC_DATABASE_URL
    connectable = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
