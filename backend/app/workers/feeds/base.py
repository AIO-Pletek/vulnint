"""Base feed connector with retry, deduplication, normalization."""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.logging import get_logger
from app.models.vulnerability import Severity

log = get_logger(__name__)


@dataclass
class FeedRecord:
    """Normalized vulnerability record produced by every feed."""
    cve_id: Optional[str] = None  # None for advisories without a CVE link
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Severity = Severity.none
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    cwe: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    kev: bool = False
    exploit_available: bool = False
    exploit_sources: List[Dict[str, Any]] = field(default_factory=list)
    affected_products: List[Dict[str, Any]] = field(default_factory=list)
    advisories: List[Dict[str, Any]] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


class BaseFeed(ABC):
    name: str = "base"
    timeout: float = 60.0
    rate_limit_per_minute: int = 60

    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(5)
        self._min_interval = 60.0 / max(1, self.rate_limit_per_minute)
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._last_call + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = asyncio.get_event_loop().time()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        await self._throttle()
        async with self._semaphore:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(5),
                wait=wait_exponential(multiplier=1, min=1, max=30),
                retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
                reraise=True,
            ):
                with attempt:
                    async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                        resp = await client.get(url, **kwargs)
                        if resp.status_code >= 500 or resp.status_code == 429:
                            resp.raise_for_status()
                        return resp
            raise RuntimeError("unreachable")

    @abstractmethod
    async def fetch(self) -> AsyncIterator[FeedRecord]:
        """Yield normalized FeedRecord items."""
        if False:
            yield  # pragma: no cover  -> tells type-checker this is async generator
