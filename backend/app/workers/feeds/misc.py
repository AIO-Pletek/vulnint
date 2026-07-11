"""CloudLinux, cPanel, MSRC, ExploitDB connectors."""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import AsyncIterator

import feedparser

from app.core.config import settings
from app.models.vulnerability import Severity
from app.workers.feeds.base import BaseFeed, FeedRecord
from app.workers.feeds.rhel_family import SEV_MAP, _parse_dt

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class CloudLinuxFeed(BaseFeed):
    name = "cloudlinux"
    rate_limit_per_minute = 20

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.CLOUDLINUX_FEED)
        feed = feedparser.parse(resp.text)
        for entry in feed.entries:
            title = entry.get("title")
            description = entry.get("summary") or entry.get("description") or ""
            published = None
            if entry.get("published_parsed"):
                try:
                    published = datetime(*entry.published_parsed[:6])
                except Exception:
                    pass
            cves = sorted(set(CVE_RE.findall(description + " " + (title or ""))))
            sev = Severity.medium
            text = (title or "").lower() + description.lower()
            for k, v in SEV_MAP.items():
                if k in text:
                    sev = v
                    break
            advisory = {
                "advisory_id": entry.get("id") or title,
                "source": "CLSA",
                "title": title,
                "summary": description,
                "severity": sev,
                "url": entry.get("link"),
                "published_at": published,
            }
            if not cves:
                yield FeedRecord(title=title, description=description, severity=sev,
                                 advisories=[advisory], published_at=published,
                                 affected_products=[{"vendor": "cloudlinux", "product": "cloudlinux",
                                                     "os_family": "cloudlinux"}],
                                 raw_data={"source": "cloudlinux"})
            else:
                for cid in cves:
                    yield FeedRecord(cve_id=cid, title=title, description=description,
                                     severity=sev, advisories=[advisory], published_at=published,
                                     affected_products=[{"vendor": "cloudlinux", "product": "cloudlinux",
                                                         "os_family": "cloudlinux"}],
                                     raw_data={"source": "cloudlinux"})


class CPanelFeed(BaseFeed):
    name = "cpanel"
    rate_limit_per_minute = 20

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.CPANEL_FEED)
        feed = feedparser.parse(resp.text)
        for entry in feed.entries:
            title = entry.get("title")
            description = entry.get("summary") or entry.get("description") or ""
            published = None
            if entry.get("published_parsed"):
                try:
                    published = datetime(*entry.published_parsed[:6])
                except Exception:
                    pass
            cves = sorted(set(CVE_RE.findall(description + " " + (title or ""))))
            # cPanel doesn't always publish numeric severity; infer
            sev = Severity.medium
            text = (title or "").lower() + description.lower()
            if "critical" in text:
                sev = Severity.critical
            elif "important" in text or "high" in text:
                sev = Severity.high

            # Try to parse fixed cPanel version like "11.110.0.4"
            fixed_version = None
            m = re.search(r"\b(\d{2}\.\d{2,3}\.\d+(?:\.\d+)?)\b", description + " " + (title or ""))
            if m:
                fixed_version = m.group(1)

            advisory = {
                "advisory_id": entry.get("id") or title,
                "source": "CPANEL-TSR",
                "title": title,
                "summary": description,
                "severity": sev,
                "url": entry.get("link"),
                "published_at": published,
            }
            affected = [{
                "vendor": "cpanel",
                "product": "cpanel",
                "package_name": "cpanel",
                "os_family": "cpanel",
                "fixed_version": fixed_version,
            }]
            if not cves:
                yield FeedRecord(title=title, description=description, severity=sev,
                                 advisories=[advisory], affected_products=affected,
                                 published_at=published, raw_data={"source": "cpanel"})
            else:
                for cid in cves:
                    yield FeedRecord(cve_id=cid, title=title, description=description,
                                     severity=sev, advisories=[advisory],
                                     affected_products=affected, published_at=published,
                                     raw_data={"source": "cpanel"})


class MSRCFeed(BaseFeed):
    """Microsoft Security Response Center CVRF API.

    Updates list: /cvrf/v3.0/updates returns months. We pull latest 2 months.
    """
    name = "msrc"
    rate_limit_per_minute = 20

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.MSRC_FEED, headers={"Accept": "application/json"})
        data = resp.json()
        updates = data.get("value", [])
        # Take 2 most recent month bulletins (e.g. 2025-Mar)
        for upd in updates[:2]:
            cvrf_url = upd.get("CvrfUrl")
            if not cvrf_url:
                continue
            r = await self.get(cvrf_url, headers={"Accept": "application/json"})
            cvrf = r.json()
            for vuln in cvrf.get("Vulnerability", []):
                cve_id = vuln.get("CVE")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue
                title_obj = vuln.get("Title") or {}
                title = title_obj.get("Value") if isinstance(title_obj, dict) else title_obj
                # CVSS
                cvss_score = None
                cvss_vector = None
                for cs in vuln.get("CVSSScoreSets", []):
                    cvss_score = cs.get("BaseScore")
                    cvss_vector = cs.get("Vector")
                    if cvss_score:
                        break
                # KBs from Remediations
                kbs: list[str] = []
                for rem in vuln.get("Remediations", []):
                    if rem.get("Type") == 0 or rem.get("URL", "").lower().__contains__("kb"):
                        d = rem.get("Description", {})
                        val = d.get("Value") if isinstance(d, dict) else d
                        if val and val.isdigit():
                            kbs.append("KB" + val)
                affected = [{
                    "vendor": "microsoft",
                    "product": "windows",
                    "package_name": "windows",
                    "os_family": "windows",
                    "fixed_version": ",".join(kbs) if kbs else None,
                }]
                yield FeedRecord(
                    cve_id=cve_id,
                    title=title,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cvss_version="3.1",
                    severity=_sev_from_score(cvss_score),
                    affected_products=affected,
                    raw_data={"source": "msrc", "kbs": kbs},
                )


def _sev_from_score(s):
    from app.utils.scoring import severity_from_cvss
    return severity_from_cvss(s)


class ExploitDBFeed(BaseFeed):
    """Exploit-DB CSV feed — maps CVEs to public exploits."""
    name = "exploitdb"
    rate_limit_per_minute = 6
    timeout = 240

    async def fetch(self) -> AsyncIterator[FeedRecord]:
        resp = await self.get(settings.EXPLOITDB_FEED)
        text = resp.text
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            cves_field = row.get("codes") or row.get("cve") or ""
            cves = sorted(set(CVE_RE.findall(cves_field)))
            if not cves:
                continue
            edb_id = row.get("id")
            url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None
            pub = _parse_dt(row.get("date_published") or row.get("date"))
            for cid in cves:
                yield FeedRecord(
                    cve_id=cid,
                    exploit_available=True,
                    exploit_sources=[{
                        "source": "exploit-db",
                        "external_id": edb_id,
                        "url": url,
                        "published_at": pub,
                    }],
                    raw_data={"source": "exploitdb"},
                )
