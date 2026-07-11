"""Ubuntu Security Notices (USN) feed.

Endpoint: https://ubuntu.com/security/notices.json — paginated JSON.
"""
from __future__ import annotations

from datetime import datetime
from typing import AsyncIterator

from app.core.config import settings
from app.models.vulnerability import Severity
from app.workers.feeds.base import BaseFeed, FeedRecord


class UbuntuUSNFeed(BaseFeed):
    name = "ubuntu_usn"
    rate_limit_per_minute = 30

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        # Ubuntu paginates with offset/limit
        offset = 0
        limit = 100
        while True:
            url = f"{settings.UBUNTU_USN_FEED}?offset={offset}&limit={limit}&order=newest"
            resp = await self.get(url)
            data = resp.json()
            notices = data.get("notices", [])
            if not notices:
                break
            for n in notices:
                async for rec in self._expand(n):
                    yield rec
            if len(notices) < limit:
                break
            offset += limit

    async def _expand(self, notice: dict) -> AsyncIterator[FeedRecord]:
        usn_id = notice.get("id")
        title = notice.get("title")
        published = _parse_dt(notice.get("published"))
        description = notice.get("summary")
        cves = notice.get("cves_ids") or notice.get("cves") or []
        # Some payloads have list of strings; some list of dicts
        cve_ids = []
        for c in cves:
            if isinstance(c, dict):
                cid = c.get("id")
                if cid:
                    cve_ids.append(cid)
            elif isinstance(c, str):
                cve_ids.append(c)

        # Build affected packages: notices contain "release_packages" keyed by Ubuntu release
        affected_packages = []
        rel_pkgs = notice.get("release_packages", {})
        for release, pkgs in rel_pkgs.items():
            for p in pkgs:
                affected_packages.append({
                    "vendor": "canonical",
                    "product": p.get("name"),
                    "package_name": p.get("name"),
                    "os_family": "ubuntu",
                    "os_version": release,
                    "fixed_version": p.get("version"),
                })

        advisory = {
            "advisory_id": usn_id,
            "source": "USN",
            "title": title,
            "summary": description,
            "severity": Severity.medium,  # USN doesn't always carry severity
            "url": f"https://ubuntu.com/security/notices/{usn_id}" if usn_id else None,
            "published_at": published,
            "affected_packages": affected_packages,
        }

        if cve_ids:
            for cid in cve_ids:
                yield FeedRecord(
                    cve_id=cid,
                    title=title,
                    description=description,
                    affected_products=affected_packages,
                    advisories=[advisory],
                    published_at=published,
                    raw_data={"source": "ubuntu_usn", "usn": usn_id},
                )
        else:
            # Standalone advisory (no linked CVE)
            yield FeedRecord(
                title=title,
                description=description,
                advisories=[advisory],
                affected_products=affected_packages,
                published_at=published,
                raw_data={"source": "ubuntu_usn", "usn": usn_id},
            )


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
