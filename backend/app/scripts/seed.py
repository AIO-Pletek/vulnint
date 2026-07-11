"""Idempotent seed: permissions, default roles, initial admin user.

Usage:
    python -m app.scripts.seed
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.permissions import ALL_PERMISSIONS, DEFAULT_ROLES
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.user import Permission, Role, RolePermission, User, UserRole

log = structlog.get_logger(__name__)


async def seed_permissions(db: AsyncSession) -> dict[str, Permission]:
    res = await db.execute(select(Permission))
    by_code = {p.code: p for p in res.scalars()}
    for code, desc in ALL_PERMISSIONS:
        if code not in by_code:
            p = Permission(code=code, description=desc)
            db.add(p)
            by_code[code] = p
    await db.flush()
    return by_code


async def seed_roles(db: AsyncSession, perms: dict[str, Permission]) -> dict[str, Role]:
    res = await db.execute(select(Role))
    by_name = {r.name: r for r in res.scalars()}
    for name, codes in DEFAULT_ROLES.items():
        role = by_name.get(name)
        if not role:
            role = Role(name=name, description=f"Default {name} role")
            db.add(role)
            await db.flush()
            by_name[name] = role
        # Sync permissions
        existing_perm_ids = (await db.execute(
            select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
        )).scalars().all()
        existing_set = set(existing_perm_ids)
        for code in codes:
            p = perms.get(code)
            if not p:
                continue
            if p.id not in existing_set:
                db.add(RolePermission(role_id=role.id, permission_id=p.id))
    await db.flush()
    return by_name


async def seed_admin(db: AsyncSession, roles: dict[str, Role]) -> User:
    res = await db.execute(select(User).where(User.email == settings.INITIAL_ADMIN_EMAIL.lower()))
    user = res.scalar_one_or_none()
    if user:
        log.info("admin_user_exists", email=user.email)
        return user
    user = User(
        email=settings.INITIAL_ADMIN_EMAIL.lower(),
        hashed_password=hash_password(settings.INITIAL_ADMIN_PASSWORD),
        full_name="Initial Admin",
        is_active=True,
        is_superuser=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    admin_role = roles.get("admin")
    if admin_role:
        db.add(UserRole(user_id=user.id, role_id=admin_role.id))
    await db.flush()
    log.info("admin_user_created", email=user.email)
    return user


async def main():
    async with AsyncSessionLocal() as db:
        perms = await seed_permissions(db)
        roles = await seed_roles(db, perms)
        await seed_admin(db, roles)
        await db.commit()
    log.info("seed_complete")


if __name__ == "__main__":
    asyncio.run(main())
