"""NVD API v2 CVE lookup.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=<cpe>
Rate limits: 5 req / 30s (no key), 50 req / 30s (with key). We keep a small
async token bucket and rely on the SQLite cache for repeat queries.
"""
from __future__ import annotations

import asyncio
import time
from typing import List, Optional

import httpx

from ..core.component import CVE, severity_from_score
from ..core.config import Settings
from ..utils.logging import get_logger
from .cache import CveCache

log = get_logger("sbomx.nvd")


class _RateLimiter:
    """Simple async sliding-window limiter."""

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._calls = [t for t in self._calls if now - t < self.period]
            if len(self._calls) >= self.max_calls:
                sleep_for = self.period - (now - self._calls[0]) + 0.1
                log.info("nvd_rate_limit_wait", seconds=round(sleep_for, 1))
                await asyncio.sleep(max(sleep_for, 0))
            self._calls.append(time.monotonic())


class NvdClient:
    def __init__(self, settings: Settings, cache: Optional[CveCache] = None):
        self.settings = settings
        self.cache = cache or CveCache(settings.cache_db, settings.cache_ttl_hours)
        max_calls = 50 if settings.nvd_api_key else 5
        self.limiter = _RateLimiter(max_calls=max_calls, period=30.0)

    async def lookup_cpe(self, cpe: str, client: httpx.AsyncClient) -> List[CVE]:
        """Look up CVEs for a CPE string, using cache and rate limiting."""
        cached = self.cache.get("nvd", cpe)
        if cached is not None:
            log.debug("nvd_cache_hit", cpe=cpe, count=len(cached))
            return cached
        if self.settings.offline:
            return []

        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        cves = await self._fetch_with_retry(cpe, client, headers)
        self.cache.put("nvd", cpe, cves)
        return cves

    @staticmethod
    def _nvd_params(cpe: str) -> dict:
        """Choose the right NVD query parameter for a CPE.

        NVD's ``cpeName`` lookup requires a concrete version (or ``-``); a ``*``
        version is rejected with 404. When we don't have a concrete version —
        common for hardware and coarse detections — query ``virtualMatchString``
        with the vendor/product prefix, which matches across all versions.
        """
        parts = cpe.split(":")
        version = parts[5] if len(parts) > 5 else "*"
        if version and version not in ("*", "-"):
            return {"cpeName": cpe}
        # cpe:2.3:<part>:<vendor>:<product>
        prefix = ":".join(parts[:5])
        return {"virtualMatchString": prefix}

    async def _fetch_with_retry(
        self, cpe: str, client: httpx.AsyncClient, headers: dict, retries: int = 3
    ) -> List[CVE]:
        params = self._nvd_params(cpe)
        for attempt in range(retries):
            await self.limiter.acquire()
            try:
                resp = await client.get(
                    self.settings.nvd_base_url,
                    params=params,
                    headers=headers,
                    timeout=self.settings.request_timeout,
                )
                if resp.status_code == 200:
                    return self._parse(resp.json())
                if resp.status_code in (403, 429, 503):
                    backoff = 2 ** attempt * 3
                    log.warning("nvd_backoff", status=resp.status_code, seconds=backoff)
                    await asyncio.sleep(backoff)
                    continue
                log.warning("nvd_unexpected_status", status=resp.status_code, cpe=cpe)
                return []
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                log.warning("nvd_request_error", error=str(exc), attempt=attempt)
                await asyncio.sleep(2 ** attempt)
        return []

    @staticmethod
    def _parse(data: dict) -> List[CVE]:
        out: List[CVE] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, vector, sev = NvdClient._extract_cvss(cve.get("metrics", {}))
            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
            out.append(
                CVE(
                    id=cve_id,
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    description=desc,
                    published=cve.get("published", "").split("T")[0] or None,
                    source="nvd",
                    references=refs,
                    nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )
        return out

    @staticmethod
    def _extract_cvss(metrics: dict):
        # Prefer CVSS v3.1, then v3.0, then v2.
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                cd = entries[0].get("cvssData", {})
                score = cd.get("baseScore")
                vector = cd.get("vectorString")
                sev = cd.get("baseSeverity") or severity_from_score(score)
                return score, vector, sev.upper() if sev else "UNKNOWN"
        entries = metrics.get("cvssMetricV2") or []
        if entries:
            cd = entries[0].get("cvssData", {})
            score = cd.get("baseScore")
            return score, cd.get("vectorString"), severity_from_score(score)
        return None, None, "UNKNOWN"
