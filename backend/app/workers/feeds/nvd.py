"""NIST NVD CVE 2.0 API connector.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req/30s without API key, 50 req/30s with key.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

from app.core.config import settings
from app.core.logging import get_logger
from app.models.vulnerability import Severity
from app.utils.scoring import severity_from_cvss
from app.workers.feeds.base import BaseFeed, FeedRecord

log = get_logger(__name__)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


class NVDFeed(BaseFeed):
    name = "nvd"
    rate_limit_per_minute = 50  # respects API-key quota

    def __init__(self, lookback_days: int = 7, page_size: int = 2000):
        super().__init__()
        if not settings.NVD_API_KEY:
            self.rate_limit_per_minute = 5
        self.lookback_days = lookback_days
        self.page_size = page_size

    def _headers(self) -> dict:
        if settings.NVD_API_KEY:
            return {"apiKey": settings.NVD_API_KEY}
        return {}

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        # Pull last N days, paginated
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.lookback_days)
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": self.page_size,
            "startIndex": 0,
        }
        total = None
        while True:
            resp = await self.get(settings.NVD_API_URL, headers=self._headers(), params=params)
            data = resp.json()
            total = data.get("totalResults", 0)
            for item in data.get("vulnerabilities", []):
                rec = self._parse_one(item.get("cve", {}))
                if rec:
                    yield rec
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total:
                break
        log.info("nvd.fetch.done", total=total)

    def _parse_one(self, cve: dict) -> FeedRecord | None:
        cve_id = cve.get("id")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)

        # CVSS — prefer v3.1 -> v3.0 -> v2
        metrics = cve.get("metrics", {})
        cvss_score: float | None = None
        cvss_vector: str | None = None
        cvss_version: str | None = None
        for key, ver in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                cvss_vector = m.get("vectorString")
                cvss_version = ver
                break

        cwe: list[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cwe.append(d["value"])

        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        # Affected products from CPE configurations
        affected_products = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    if not cm.get("vulnerable"):
                        continue
                    cpe = cm.get("criteria", "")
                    parts = cpe.split(":")
                    vendor = parts[3] if len(parts) > 4 else None
                    product = parts[4] if len(parts) > 5 else None
                    if not product:
                        continue
                    affected_products.append({
                        "vendor": vendor,
                        "product": product,
                        "package_name": product,
                        "affected_version_range": _range_from_cpe(cm),
                        "cpe": cpe,
                        "os_family": _guess_os_family(vendor, product),
                    })

        return FeedRecord(
            cve_id=cve_id,
            title=cve_id,
            description=desc,
            severity=severity_from_cvss(cvss_score),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            cwe=cwe,
            references=list(filter(None, refs)),
            published_at=_parse_dt(cve.get("published")),
            modified_at=_parse_dt(cve.get("lastModified")),
            affected_products=affected_products,
            raw_data={"source": "nvd"},
        )


def _range_from_cpe(cm: dict) -> str:
    parts = []
    if cm.get("versionStartIncluding"):
        parts.append(f">= {cm['versionStartIncluding']}")
    if cm.get("versionStartExcluding"):
        parts.append(f"> {cm['versionStartExcluding']}")
    if cm.get("versionEndIncluding"):
        parts.append(f"<= {cm['versionEndIncluding']}")
    if cm.get("versionEndExcluding"):
        parts.append(f"< {cm['versionEndExcluding']}")
    return ", ".join(parts)


def _guess_os_family(vendor: str | None, product: str | None) -> str | None:
    if not vendor:
        return None
    v = vendor.lower()
    if v in ("canonical",) or (product and "ubuntu" in product.lower()):
        return "ubuntu"
    if v == "debian":
        return "debian"
    if v in ("almalinux",) or (product and "almalinux" in (product or "").lower()):
        return "almalinux"
    if v == "rocky" or (product and "rocky" in (product or "").lower()):
        return "rocky"
    if v == "cloudlinux":
        return "cloudlinux"
    if v == "microsoft":
        return "windows"
    if v == "cpanel":
        return "cpanel"
    return None
