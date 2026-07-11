"""Celery tasks for OpenSearch indexing."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.opensearch import bulk_index_cves, ensure_indices
from app.models.vulnerability import CVE, AffectedProduct, ExploitSource
from app.workers.celery_app import celery_app

log = structlog.get_logger(__name__)

BATCH_SIZE = 500


def _serialize_cve(cve: CVE, affected: list[AffectedProduct], exploits: list[ExploitSource]) -> dict[str, Any]:
    os_targets = sorted({a.os_family for a in affected if a.os_family})
    vendors = sorted({a.vendor for a in affected if a.vendor})
    products = sorted({a.product for a in affected if a.product})
    return {
        "cve_id": cve.cve_id,
        "title": cve.title,
        "description": cve.description,
        "severity": cve.severity.value if cve.severity else None,
        "cvss_score": cve.cvss_score,
        "cvss_vector": cve.cvss_vector,
        "cvss_version": cve.cvss_version,
        "cwe": list(cve.cwe or []),
        "kev": bool(cve.kev),
        "exploit_available": bool(cve.exploit_available),
        "risk_score": cve.risk_score,
        "published_at": cve.published_at.isoformat() if cve.published_at else None,
        "modified_at": cve.modified_at.isoformat() if cve.modified_at else None,
        "vendors": vendors,
        "products": products,
        "os_targets": os_targets,
        "references": list(cve.references or []),
        "exploit_sources": [{"source": e.source, "url": e.url} for e in exploits],
        "affected_count": len(affected),
    }


async def _index_by_cve_ids(cve_ids: list[str]) -> int:
    if not cve_ids:
        return 0
    async with AsyncSessionLocal() as db:
        rows = await db.execute(select(CVE).where(CVE.cve_id.in_(cve_ids)))
        cves = list(rows.scalars())
        if not cves:
            return 0
        ap = await db.execute(select(AffectedProduct).where(AffectedProduct.cve_pk.in_([c.id for c in cves])))
        ap_by_cve: dict[Any, list[AffectedProduct]] = {}
        for a in ap.scalars():
            ap_by_cve.setdefault(a.cve_pk, []).append(a)
        ex = await db.execute(select(ExploitSource).where(ExploitSource.cve_pk.in_([c.id for c in cves])))
        ex_by_cve: dict[Any, list[ExploitSource]] = {}
        for e in ex.scalars():
            ex_by_cve.setdefault(e.cve_pk, []).append(e)

        docs = [_serialize_cve(c, ap_by_cve.get(c.id, []), ex_by_cve.get(c.id, [])) for c in cves]
        # bulk_index_cves is sync (opensearch-py); call directly
        bulk_index_cves(docs)
        return len(docs)


async def _index_modified_since(since: datetime) -> int:
    total = 0
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CVE.cve_id).where(CVE.modified_at >= since).order_by(CVE.modified_at)
        )
        ids = [r[0] for r in result.all()]
    for i in range(0, len(ids), BATCH_SIZE):
        total += await _index_by_cve_ids(ids[i : i + BATCH_SIZE])
    return total


@celery_app.task(name="opensearch.index_cves", queue="default")
def index_cves(cve_ids: list[str]) -> dict[str, Any]:
    n = asyncio.run(_index_by_cve_ids(cve_ids))
    return {"indexed": n}


@celery_app.task(name="opensearch.reindex_modified", queue="default")
def reindex_modified(hours: int = 2) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    ensure_indices()
    n = asyncio.run(_index_modified_since(since))
    log.info("opensearch_reindex_modified_done", hours=hours, indexed=n)
    return {"indexed": n, "since": since.isoformat()}


@celery_app.task(name="opensearch.reindex_all", queue="default")
def reindex_all() -> dict[str, Any]:
    ensure_indices()
    n = asyncio.run(_index_modified_since(datetime(1970, 1, 1, tzinfo=timezone.utc)))
    log.info("opensearch_reindex_all_done", indexed=n)
    return {"indexed": n}
