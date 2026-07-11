"""CISA Known Exploited Vulnerabilities catalog.

JSON feed with the canonical list of actively exploited CVEs.
"""
from __future__ import annotations

from datetime import datetime
from typing import AsyncIterator

from app.core.config import settings
from app.workers.feeds.base import BaseFeed, FeedRecord


class CISAKEVFeed(BaseFeed):
    name = "cisa_kev"
    rate_limit_per_minute = 30

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.CISA_KEV_FEED)
        data = resp.json()
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            added = None
            if v.get("dateAdded"):
                try:
                    added = datetime.strptime(v["dateAdded"], "%Y-%m-%d")
                except ValueError:
                    added = None
            yield FeedRecord(
                cve_id=cve_id,
                title=v.get("vulnerabilityName") or cve_id,
                description=v.get("shortDescription"),
                kev=True,
                exploit_available=True,
                published_at=added,
                exploit_sources=[{"source": "cisa-kev", "external_id": cve_id,
                                  "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                  "published_at": added}],
                raw_data={"source": "cisa_kev", **v},
            )
