"""Debian Security Tracker.

JSON dump: https://security-tracker.debian.org/tracker/data/json
Structure: { package: { CVE: { releases: { release: { status, fixed_version, urgency } } } } }
"""
from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.models.vulnerability import Severity
from app.workers.feeds.base import BaseFeed, FeedRecord


URGENCY_MAP = {
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "not yet assigned": Severity.none,
    "unimportant": Severity.low,
    "end-of-life": Severity.none,
}


class DebianFeed(BaseFeed):
    name = "debian"
    rate_limit_per_minute = 10
    timeout = 180

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.DEBIAN_DSA_FEED)
        data = resp.json()
        # Group by CVE: map cve_id -> list of (package, release, fixed_version, urgency)
        cve_map: dict[str, list[dict]] = {}
        for package, cves in data.items():
            if not isinstance(cves, dict):
                continue
            for cve_id, info in cves.items():
                if not isinstance(info, dict) or not cve_id.startswith("CVE-"):
                    continue
                releases = info.get("releases", {})
                for rel, rel_info in releases.items():
                    status = rel_info.get("status")
                    if status == "resolved":
                        cve_map.setdefault(cve_id, []).append({
                            "vendor": "debian",
                            "product": package,
                            "package_name": package,
                            "os_family": "debian",
                            "os_version": rel,
                            "fixed_version": rel_info.get("fixed_version"),
                        })
                    elif status == "open":
                        cve_map.setdefault(cve_id, []).append({
                            "vendor": "debian",
                            "product": package,
                            "package_name": package,
                            "os_family": "debian",
                            "os_version": rel,
                            "fixed_version": None,
                        })
        for cve_id, products in cve_map.items():
            yield FeedRecord(
                cve_id=cve_id,
                affected_products=products,
                raw_data={"source": "debian"},
            )
