"""Build OpenSearch query DSL from API search params."""
from __future__ import annotations

from typing import Any

from app.core.opensearch import CVE_INDEX, get_opensearch


def search_cves(
    *,
    q: str | None = None,
    severity: list[str] | None = None,
    os_families: list[str] | None = None,
    vendors: list[str] | None = None,
    kev: bool | None = None,
    exploit_available: bool | None = None,
    min_cvss: float | None = None,
    sort: str = "modified_at",
    order: str = "desc",
    page: int = 1,
    size: int = 25,
) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    filt: list[dict[str, Any]] = []

    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": ["cve_id^4", "title^2", "description", "products^2", "vendors", "cwe"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        })

    if severity:
        filt.append({"terms": {"severity": [s.lower() for s in severity]}})
    if os_families:
        filt.append({"terms": {"os_targets": [o.lower() for o in os_families]}})
    if vendors:
        filt.append({"terms": {"vendors": [v.lower() for v in vendors]}})
    if kev is not None:
        filt.append({"term": {"kev": kev}})
    if exploit_available is not None:
        filt.append({"term": {"exploit_available": exploit_available}})
    if min_cvss is not None:
        filt.append({"range": {"cvss_score": {"gte": min_cvss}}})

    body: dict[str, Any] = {
        "query": {"bool": {"must": must or [{"match_all": {}}], "filter": filt}},
        "from": max(0, (page - 1) * size),
        "size": min(size, 200),
        "sort": [{sort: {"order": order, "missing": "_last"}}],
        "aggs": {
            "by_severity": {"terms": {"field": "severity"}},
            "by_os_family": {"terms": {"field": "os_targets", "size": 20}},
            "kev_count": {"filter": {"term": {"kev": True}}},
            "exploit_count": {"filter": {"term": {"exploit_available": True}}},
        },
    }

    client = get_opensearch()
    res = client.search(index=CVE_INDEX, body=body)
    hits = res.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = [h["_source"] for h in hits.get("hits", [])]
    aggs = res.get("aggregations", {})
    return {
        "total": total,
        "page": page,
        "size": size,
        "items": items,
        "aggregations": {
            "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])},
            "by_os_family": {b["key"]: b["doc_count"] for b in aggs.get("by_os_family", {}).get("buckets", [])},
            "kev_count": aggs.get("kev_count", {}).get("doc_count", 0),
            "exploit_count": aggs.get("exploit_count", {}).get("doc_count", 0),
        },
    }
