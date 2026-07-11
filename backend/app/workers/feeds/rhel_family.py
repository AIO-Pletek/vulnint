"""AlmaLinux and Rocky Linux errata feeds.

AlmaLinux: RSS XML at https://errata.almalinux.org/feed/errata-rss.xml
Rocky:     JSON API at https://errata.rockylinux.org/api/v2/advisories
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import AsyncIterator

import feedparser

from app.core.config import settings
from app.models.vulnerability import Severity
from app.workers.feeds.base import BaseFeed, FeedRecord


SEV_MAP = {
    "critical": Severity.critical,
    "important": Severity.high,
    "moderate": Severity.medium,
    "low": Severity.low,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class AlmaLinuxFeed(BaseFeed):
    name = "almalinux"
    rate_limit_per_minute = 20

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.ALMALINUX_ERRATA_FEED)
        feed = feedparser.parse(resp.text)
        for entry in feed.entries:
            advisory_id = entry.get("title", "").split(":")[0].strip() if entry.get("title") else None
            published = None
            if entry.get("published"):
                try:
                    published = datetime(*entry.published_parsed[:6])
                except Exception:
                    pass
            description = entry.get("summary") or entry.get("description") or ""
            cves = sorted(set(CVE_RE.findall(description + " " + (entry.get("title") or ""))))
            severity = Severity.medium
            for k, v in SEV_MAP.items():
                if k in (entry.get("title") or "").lower():
                    severity = v
                    break

            advisory = {
                "advisory_id": advisory_id,
                "source": "ALSA",
                "title": entry.get("title"),
                "summary": description,
                "severity": severity,
                "url": entry.get("link"),
                "published_at": published,
            }
            if not cves:
                yield FeedRecord(
                    title=entry.get("title"),
                    description=description,
                    severity=severity,
                    advisories=[advisory],
                    published_at=published,
                    raw_data={"source": "almalinux"},
                )
            else:
                for cid in cves:
                    yield FeedRecord(
                        cve_id=cid,
                        title=entry.get("title"),
                        description=description,
                        severity=severity,
                        advisories=[advisory],
                        published_at=published,
                        affected_products=[{
                            "vendor": "almalinux",
                            "product": "almalinux",
                            "os_family": "almalinux",
                        }],
                        raw_data={"source": "almalinux"},
                    )


class RockyFeed(BaseFeed):
    name = "rocky"
    rate_limit_per_minute = 20

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        # Rocky API supports pagination via ?page=
        page = 1
        while True:
            resp = await self.get(f"{settings.ROCKY_ERRATA_FEED}?page={page}&size=100")
            data = resp.json()
            items = data.get("advisories") or data.get("data") or []
            if not items:
                break
            for adv in items:
                for rec in self._process(adv):
                    yield rec
            if len(items) < 100:
                break
            page += 1
            if page > 50:  # safety bound
                break

    def _process(self, adv: dict):
        advisory_id = adv.get("name") or adv.get("id")
        title = adv.get("synopsis") or advisory_id
        description = adv.get("description") or ""
        url = f"https://errata.rockylinux.org/{advisory_id}" if advisory_id else None
        sev = Severity.medium
        sev_str = (adv.get("severity") or "").lower()
        for k, v in SEV_MAP.items():
            if k == sev_str:
                sev = v
                break
        cves = adv.get("cves") or []
        if isinstance(cves, list) and cves and isinstance(cves[0], dict):
            cves = [c.get("name") for c in cves if c.get("name")]

        advisory = {
            "advisory_id": advisory_id,
            "source": "RLSA",
            "title": title,
            "summary": description,
            "severity": sev,
            "url": url,
            "published_at": _parse_dt(adv.get("published_at") or adv.get("publishedAt")),
        }
        affected = [{
            "vendor": "rocky",
            "product": "rocky",
            "os_family": "rocky",
        }]
        if not cves:
            yield FeedRecord(title=title, description=description, severity=sev,
                             advisories=[advisory], affected_products=affected,
                             raw_data={"source": "rocky"})
        else:
            for cid in cves:
                yield FeedRecord(cve_id=cid, title=title, description=description,
                                 severity=sev, advisories=[advisory],
                                 affected_products=affected,
                                 raw_data={"source": "rocky"})


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None
