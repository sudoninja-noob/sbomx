"""Aggregate CVE results from NVD + OSV across all components.

Runs lookups concurrently with asyncio + httpx, deduplicates by CVE id,
prefers the record with the richer CVSS data, and sorts by severity.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List

import httpx

from ..core.component import CVE, Component, SEVERITY_ORDER
from ..core.config import Settings
from ..utils.logging import get_logger
from .cache import CveCache
from .nvd import NvdClient
from .osv import OsvClient

log = get_logger("sbomx.aggregator")


def _merge_cve(existing: CVE, new: CVE) -> CVE:
    """Combine two records for the same CVE id, keeping the best data."""
    if existing.cvss_score is None and new.cvss_score is not None:
        existing.cvss_score = new.cvss_score
        existing.cvss_vector = new.cvss_vector
        existing.severity = new.severity
    if not existing.description and new.description:
        existing.description = new.description
    if not existing.published and new.published:
        existing.published = new.published
    existing.references = sorted(set(existing.references) | set(new.references))
    if new.source not in existing.source:
        existing.source = f"{existing.source}+{new.source}"
    return existing


def _dedup_and_sort(cves: List[CVE]) -> List[CVE]:
    by_id: Dict[str, CVE] = {}
    for cve in cves:
        if cve.id in by_id:
            by_id[cve.id] = _merge_cve(by_id[cve.id], cve)
        else:
            by_id[cve.id] = cve
    merged = list(by_id.values())
    merged.sort(
        key=lambda c: (SEVERITY_ORDER.get(c.severity, 0), c.cvss_score or 0.0),
        reverse=True,
    )
    return merged


class CveAggregator:
    def __init__(self, settings: Settings, sources: str = "all"):
        self.settings = settings
        # sources: "all" | "nvd" | "osv" — which CVE databases to query.
        self.sources = sources
        self.cache = CveCache(settings.cache_db, settings.cache_ttl_hours)
        self.nvd = NvdClient(settings, self.cache)
        self.osv = OsvClient(settings, self.cache)

    async def _lookup_component(
        self, comp: Component, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> Component:
        async with sem:
            results: List[CVE] = []
            if comp.cpe and self.sources in ("all", "nvd"):
                results.extend(await self.nvd.lookup_cpe(comp.cpe, client))
            # OSV is a software-ecosystem database; skip it for hardware parts.
            if self.sources in ("all", "osv") and not comp.is_hardware:
                results.extend(await self.osv.lookup(comp, client))
            comp.cves = [c.to_dict() for c in _dedup_and_sort(results)]
            return comp

    async def enrich_async(self, components: List[Component], progress=None) -> List[Component]:
        sem = asyncio.Semaphore(8)
        async with httpx.AsyncClient() as client:
            tasks = [self._lookup_component(c, client, sem) for c in components]
            out = []
            for coro in asyncio.as_completed(tasks):
                comp = await coro
                out.append(comp)
                if progress is not None:
                    progress()
            return components  # components mutated in place; preserve order

    def enrich(self, components: List[Component], progress=None) -> List[Component]:
        """Synchronous wrapper around the async enrichment pipeline."""
        return asyncio.run(self.enrich_async(components, progress))
