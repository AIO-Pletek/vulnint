"""OpenSearch client and index helpers."""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Iterable

from opensearchpy import OpenSearch, helpers

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

CVE_INDEX = "vulnint-cves"

CVE_INDEX_MAPPING: Dict[str, Any] = {
    "settings": {
        "analysis": {
            "analyzer": {
                "lowercase_keyword": {"type": "custom", "tokenizer": "keyword", "filter": ["lowercase"]}
            }
        },
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "cve_id": {"type": "keyword"},
            "title": {"type": "text"},
            "description": {"type": "text"},
            "severity": {"type": "keyword"},
            "cvss_score": {"type": "float"},
            "cvss_vector": {"type": "keyword"},
            "cwe": {"type": "keyword"},
            "kev": {"type": "boolean"},
            "exploit_available": {"type": "boolean"},
            "exploit_sources": {"type": "keyword"},
            "vendors": {"type": "keyword"},
            "products": {"type": "keyword"},
            "os_targets": {"type": "keyword"},
            "references": {"type": "keyword"},
            "advisories": {"type": "keyword"},
            "fixed_versions": {"type": "keyword"},
            "published_at": {"type": "date"},
            "modified_at": {"type": "date"},
            "ingested_at": {"type": "date"},
            "risk_score": {"type": "float"},
        }
    },
}


@lru_cache
def get_opensearch() -> OpenSearch:
    return OpenSearch(
        hosts=[settings.OPENSEARCH_URL],
        use_ssl=settings.OPENSEARCH_USE_SSL,
        verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
        ssl_show_warn=False,
        timeout=30,
    )


def ensure_indices() -> None:
    client = get_opensearch()
    try:
        if not client.indices.exists(index=CVE_INDEX):
            client.indices.create(index=CVE_INDEX, body=CVE_INDEX_MAPPING)
            log.info("opensearch.index_created", index=CVE_INDEX)
    except Exception as e:
        log.error("opensearch.index_create_failed", error=str(e))


def bulk_index_cves(docs: Iterable[Dict[str, Any]]) -> int:
    client = get_opensearch()
    actions = (
        {"_op_type": "index", "_index": CVE_INDEX, "_id": d["cve_id"], "_source": d}
        for d in docs
    )
    success, errors = helpers.bulk(client, actions, raise_on_error=False, stats_only=False)
    if errors:
        log.warning("opensearch.bulk_errors", count=len(errors))
    return success


def search_cves(query: Dict[str, Any], size: int = 25, from_: int = 0,
                sort: list | None = None) -> Dict[str, Any]:
    client = get_opensearch()
    body: Dict[str, Any] = {"query": query, "from": from_, "size": size}
    if sort:
        body["sort"] = sort
    return client.search(index=CVE_INDEX, body=body)
