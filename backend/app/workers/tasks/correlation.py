"""Correlation tasks: match installed packages against affected CVEs."""
from __future__ import annotations

import asyncio
import uuid
from typing import List

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.core.logging import configure_logging, get_logger
from app.models.server import InstalledPackage, Inventory, Server
from app.models.vulnerability import (
    AffectedProduct, CVE, Correlation, CorrelationStatus, Severity,
)
from app.repositories.server import CorrelationRepo
from app.utils.versioning import (
    cpanel_is_vulnerable, is_vulnerable, kb_matches,
)
from app.workers.celery_app import celery_app

configure_logging()
log = get_logger(__name__)


async def _correlate_server(server_id: uuid.UUID) -> dict:
    """Run full correlation for one server.

    Strategy: load latest packages, then for each affected product where
    os_family matches the server, compare versions. New matches become open
    correlations; existing correlations whose installed version is now >= fix
    are marked fixed.
    """
    async with AsyncSessionLocal() as db:
        srv = (await db.execute(
            select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
        )).scalar_one_or_none()
        if not srv:
            return {"server_id": str(server_id), "status": "not_found"}

        latest_inv = (await db.execute(
            select(Inventory.id).where(Inventory.server_id == server_id)
            .order_by(Inventory.collected_at.desc()).limit(1)
        )).scalar_one_or_none()
        if not latest_inv:
            return {"server_id": str(server_id), "status": "no_inventory"}

        pkgs = (await db.execute(
            select(InstalledPackage).where(InstalledPackage.inventory_id == latest_inv)
        )).scalars().all()
        pkg_index: dict[str, list[InstalledPackage]] = {}
        installed_kbs: list[str] = []
        for p in pkgs:
            if p.source == "kb":
                installed_kbs.append(p.name)
            pkg_index.setdefault(p.name.lower(), []).append(p)
        cpanel_installed = srv.cpanel_version

        os_fam = srv.os_family.value if hasattr(srv.os_family, "value") else srv.os_family

        # Pull all AffectedProducts whose os_family matches this server
        # plus those with no os_family that match by package name
        af_q = select(AffectedProduct).where(
            (AffectedProduct.os_family == os_fam) | (AffectedProduct.os_family.is_(None))
        ).options(selectinload(AffectedProduct.cve))
        affected = (await db.execute(af_q)).scalars().all()

        new_correlations = 0
        fixed_correlations = 0
        repo = CorrelationRepo(db)

        for ap in affected:
            cve = ap.cve
            if not cve:
                continue

            # cPanel logic
            if os_fam == "cpanel" and ap.os_family == "cpanel":
                if cpanel_installed and ap.fixed_version:
                    if cpanel_is_vulnerable(cpanel_installed, ap.fixed_version):
                        _, is_new = await repo.upsert(
                            srv.id, cve.id, "cpanel", cpanel_installed,
                            ap.fixed_version, cve.severity,
                        )
                        if is_new:
                            new_correlations += 1
                continue

            # Windows KB logic
            if os_fam == "windows":
                # MSRC packs KBs into fixed_version (comma-separated). If host has any -> patched.
                required_kbs = [k.strip() for k in (ap.fixed_version or "").split(",") if k.strip()]
                if required_kbs and not any(kb_matches(installed_kbs, k) for k in required_kbs):
                    _, is_new = await repo.upsert(
                        srv.id, cve.id,
                        "windows", srv.os_version or "unknown",
                        ",".join(required_kbs), cve.severity,
                    )
                    if is_new:
                        new_correlations += 1
                continue

            # Linux package logic
            if not ap.package_name:
                continue
            installed_list = pkg_index.get(ap.package_name.lower())
            if not installed_list:
                continue
            for installed in installed_list:
                if is_vulnerable(installed.version, ap.fixed_version, os_fam):
                    _, is_new = await repo.upsert(
                        srv.id, cve.id, installed.name, installed.version,
                        ap.fixed_version, cve.severity,
                    )
                    if is_new:
                        new_correlations += 1

        # Mark fixed: existing OPEN correlations where installed >= fixed
        opens = (await db.execute(
            select(Correlation).where(
                Correlation.server_id == srv.id,
                Correlation.status == CorrelationStatus.open,
            )
        )).scalars().all()
        for c in opens:
            installed_pkgs = pkg_index.get(c.package_name.lower(), [])
            if not installed_pkgs:
                continue
            still_vuln = False
            for ip in installed_pkgs:
                if is_vulnerable(ip.version, c.fixed_version, os_fam):
                    still_vuln = True
                    break
            if not still_vuln:
                await repo.mark_fixed(srv.id, c.cve_pk, c.package_name)
                fixed_correlations += 1

        log.info("correlation.server.done",
                 server=str(srv.id), new=new_correlations, fixed=fixed_correlations)
        return {
            "server_id": str(srv.id),
            "new_correlations": new_correlations,
            "fixed": fixed_correlations,
        }


async def _correlate_for_cves(cve_ids: List[str]) -> dict:
    """When a set of CVEs is updated, recompute correlations across all servers."""
    if not cve_ids:
        return {"checked": 0}
    async with AsyncSessionLocal() as db:
        # Quick pass: find candidate servers via affected_products
        cve_pks = (await db.execute(
            select(CVE.id).where(CVE.cve_id.in_(cve_ids))
        )).scalars().all()
        if not cve_pks:
            return {"checked": 0}
        servers = (await db.execute(
            select(Server.id).where(Server.deleted_at.is_(None), Server.is_active.is_(True))
        )).scalars().all()
    # Run all in parallel
    results = await asyncio.gather(*[_correlate_server(sid) for sid in servers])
    return {"checked_servers": len(servers), "results": results}


@celery_app.task(name="correlation.run_for_server")
def run_for_server(server_id: str) -> dict:
    return asyncio.run(_correlate_server(uuid.UUID(server_id)))


@celery_app.task(name="correlation.run_for_cves")
def run_for_cves(cve_ids: List[str]) -> dict:
    return asyncio.run(_correlate_for_cves(cve_ids))


@celery_app.task(name="correlation.run_all")
def run_all() -> dict:
    async def _all():
        async with AsyncSessionLocal() as db:
            servers = (await db.execute(
                select(Server.id).where(Server.deleted_at.is_(None), Server.is_active.is_(True))
            )).scalars().all()
        results = []
        for sid in servers:
            try:
                results.append(await _correlate_server(sid))
            except Exception as e:
                log.error("correlation.run_all.error", server=str(sid), error=str(e))
        return {"servers": len(servers), "results": results}
    return asyncio.run(_all())
