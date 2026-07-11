"""Celery tasks: feed ingestion."""
from __future__ import annotations

import asyncio
from typing import List

from app.core.database import AsyncSessionLocal
from app.core.logging import configure_logging, get_logger
from app.repositories.cve import AdvisoryRepo, CVERepo
from app.workers.celery_app import celery_app
from app.workers.feeds.base import FeedRecord
from app.workers.feeds.cisa_kev import CISAKEVFeed
from app.workers.feeds.debian import DebianFeed
from app.workers.feeds.misc import (
    CloudLinuxFeed, CPanelFeed, ExploitDBFeed, MSRCFeed,
)
from app.workers.feeds.nvd import NVDFeed
from app.workers.feeds.rhel_family import AlmaLinuxFeed, RockyFeed
from app.workers.feeds.ubuntu import UbuntuUSNFeed

configure_logging()
log = get_logger(__name__)


FEED_REGISTRY = {
    "nvd": NVDFeed,
    "cisa_kev": CISAKEVFeed,
    "ubuntu_usn": UbuntuUSNFeed,
    "debian": DebianFeed,
    "almalinux": AlmaLinuxFeed,
    "rocky": RockyFeed,
    "cloudlinux": CloudLinuxFeed,
    "msrc": MSRCFeed,
    "cpanel": CPanelFeed,
    "exploitdb": ExploitDBFeed,
}


async def _ingest_record(rec: FeedRecord) -> int:
    """Persist a normalized record into Postgres. Returns 1 if a CVE was upserted."""
    if not rec.cve_id and not rec.advisories:
        return 0

    async with AsyncSessionLocal() as db:
        cve_repo = CVERepo(db)
        adv_repo = AdvisoryRepo(db)

        cve_pk = None
        if rec.cve_id:
            payload = {
                "cve_id": rec.cve_id,
                "title": rec.title,
                "description": rec.description,
                "severity": rec.severity,
                "cvss_score": rec.cvss_score,
                "cvss_vector": rec.cvss_vector,
                "cvss_version": rec.cvss_version,
                "cwe": rec.cwe or [],
                "references": rec.references or [],
                "kev": rec.kev,
                "exploit_available": rec.exploit_available,
                "published_at": rec.published_at,
                "modified_at": rec.modified_at,
                "raw_data": rec.raw_data,
            }
            cve = await cve_repo.upsert(payload)
            cve_pk = cve.id

            # Affected products: replace if we have any (some feeds only enrich)
            if rec.affected_products:
                cleaned = [
                    {k: v for k, v in p.items()
                     if k in {"vendor", "product", "os_family", "os_version",
                              "package_name", "affected_version_range",
                              "fixed_version", "cpe"}}
                    for p in rec.affected_products if p.get("product")
                ]
                if cleaned:
                    # Merge: only replace if this source is authoritative
                    # NVD provides the most product entries; distro feeds add fixed_version.
                    await cve_repo.replace_affected_products(cve_pk, cleaned)

            # Exploit sources
            for es in rec.exploit_sources:
                await cve_repo.add_exploit_source(
                    cve_pk,
                    source=es.get("source", "unknown"),
                    external_id=es.get("external_id"),
                    url=es.get("url", ""),
                    published_at=es.get("published_at"),
                )
            await db.commit()

        # Advisories
        for adv in rec.advisories:
            if not adv.get("advisory_id") or not adv.get("source"):
                continue
            adv_payload = {**adv, "cve_id_ref": cve_pk}
            await adv_repo.upsert(adv_payload)

        return 1 if rec.cve_id else 0


async def _run_feed(name: str) -> dict:
    cls = FEED_REGISTRY.get(name)
    if not cls:
        raise ValueError(f"Unknown feed: {name}")
    feed = cls()
    log.info("feed.start", name=name)
    count = 0
    errors = 0
    cve_ids_to_index: list[str] = []
    async for rec in feed.fetch():
        try:
            await _ingest_record(rec)
            count += 1
            if rec.cve_id:
                cve_ids_to_index.append(rec.cve_id)
        except Exception as e:
            errors += 1
            log.error("feed.ingest_error", feed=name, error=str(e))
    log.info("feed.done", name=name, count=count, errors=errors)

    # Trigger index batch + correlation cycle
    if cve_ids_to_index:
        celery_app.send_task("opensearch.index_cves", args=[list(set(cve_ids_to_index))])
        celery_app.send_task("correlation.run_for_cves", args=[list(set(cve_ids_to_index))])
    return {"feed": name, "ingested": count, "errors": errors}


@celery_app.task(name="feeds.run", bind=True, max_retries=3, default_retry_delay=120)
def run_feed(self, name: str) -> dict:
    try:
        return asyncio.run(_run_feed(name))
    except Exception as e:
        log.error("feeds.run.exception", feed=name, error=str(e))
        raise self.retry(exc=e)


@celery_app.task(name="feeds.run_group")
def run_group(names: List[str]) -> list:
    results = []
    for n in names:
        try:
            results.append(asyncio.run(_run_feed(n)))
        except Exception as e:
            log.error("feeds.run_group.error", feed=n, error=str(e))
            results.append({"feed": n, "error": str(e)})
    return results


@celery_app.task(name="feeds.run_all")
def run_all() -> list:
    return run_group(list(FEED_REGISTRY.keys()))
