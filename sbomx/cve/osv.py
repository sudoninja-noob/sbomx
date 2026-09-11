"""OSV API CVE lookup (https://osv.dev).

Endpoint: POST https://api.osv.dev/v1/query
No API key required. We query by purl when available, otherwise by
(name, ecosystem, version).
"""
from __future__ import annotations

from typing import List, Optional

import httpx

from ..core.component import CVE, Component, severity_from_score
from ..core.config import Settings
from ..utils.logging import get_logger
from .cache import CveCache

log = get_logger("sbomx.osv")

# Map our purl/type hints to OSV ecosystems.
_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
}


class OsvClient:
    def __init__(self, settings: Settings, cache: Optional[CveCache] = None):
        self.settings = settings
        self.cache = cache or CveCache(settings.cache_db, settings.cache_ttl_hours)

    def _build_query(self, comp: Component) -> tuple[dict, str]:
        """Return (request_body, cache_key)."""
        if comp.purl and comp.purl.startswith("pkg:") and "generic" not in comp.purl:
            body = {"package": {"purl": comp.purl}}
            return body, f"purl:{comp.purl}"
        ecosystem = self._guess_ecosystem(comp)
        if ecosystem:
            body = {
                "version": comp.version,
                "package": {"name": comp.name, "ecosystem": ecosystem},
            }
            return body, f"{ecosystem}:{comp.name}:{comp.version}"
        # Fall back to a bare purl (OSV still resolves many generic names).
        purl = comp.purl or f"pkg:generic/{comp.name}@{comp.version}"
        return {"package": {"purl": purl}}, f"purl:{purl}"

    @staticmethod
    def _guess_ecosystem(comp: Component) -> Optional[str]:
        if comp.purl:
            ptype = comp.purl.split(":", 1)[-1].split("/", 1)[0]
            if ptype in _ECOSYSTEM_MAP:
                return _ECOSYSTEM_MAP[ptype]
        return None

    async def lookup(self, comp: Component, client: httpx.AsyncClient) -> List[CVE]:
        body, cache_key = self._build_query(comp)
        cached = self.cache.get("osv", cache_key)
        if cached is not None:
            return cached
        if self.settings.offline:
            return []
        try:
            resp = await client.post(
                self.settings.osv_base_url,
                json=body,
                timeout=self.settings.request_timeout,
            )
            if resp.status_code != 200:
                log.warning("osv_unexpected_status", status=resp.status_code)
                return []
            cves = self._parse(resp.json())
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            log.warning("osv_request_error", error=str(exc))
            return []
        self.cache.put("osv", cache_key, cves)
        return cves

    @staticmethod
    def _parse(data: dict) -> List[CVE]:
        out: List[CVE] = []
        for vuln in data.get("vulns", []) or []:
            vid = vuln.get("id", "")
            aliases = vuln.get("aliases", []) or []
            # Prefer the CVE id if present among aliases.
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vid)
            score, vector = OsvClient._extract_cvss(vuln.get("severity", []))
            sev = severity_from_score(score)
            refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")]
            out.append(
                CVE(
                    id=cve_id,
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    description=vuln.get("summary") or vuln.get("details", "")[:500],
                    published=(vuln.get("published", "") or "").split("T")[0] or None,
                    source="osv",
                    references=refs,
                    nvd_url=(
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        if cve_id.startswith("CVE-")
                        else f"https://osv.dev/vulnerability/{vid}"
                    ),
                )
            )
        return out

    @staticmethod
    def _extract_cvss(severity_list):
        for s in severity_list or []:
            vector = s.get("score")
            if s.get("type", "").startswith("CVSS") and vector:
                score = _cvss_vector_to_score(vector)
                return score, vector
        return None, None


def _cvss_vector_to_score(vector: str) -> Optional[float]:
    """OSV returns a CVSS vector string, not a base score. We compute the
    CVSS v3.1 base score from the vector so severity banding works offline.
    """
    try:
        return _compute_cvss31_base(vector)
    except Exception:  # pragma: no cover - defensive
        return None


# --- Minimal CVSS v3.1 base score calculator --------------------------------
# Implements the official CVSS v3.1 base-score equations so we do not need an
# extra dependency just to turn an OSV vector into a number.

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    import math

    return math.ceil(x * 10) / 10


def _compute_cvss31_base(vector: str) -> Optional[float]:
    parts = dict(
        p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS")
    )
    try:
        av = _W["AV"][parts["AV"]]
        ac = _W["AC"][parts["AC"]]
        ui = _W["UI"][parts["UI"]]
        scope = parts["S"]
        pr = _W["PR_C" if scope == "C" else "PR_U"][parts["PR"]]
        c = _W["CIA"][parts["C"]]
        i = _W["CIA"][parts["I"]]
        a = _W["CIA"][parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "C":
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)
    return _roundup(base)
