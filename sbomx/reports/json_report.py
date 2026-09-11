"""JSON CVE report generation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List

from .. import __version__, TOOL_NAME
from ..core.component import Component


def compute_summary(components: List[Component]) -> Dict:
    """Roll up CVE counts by severity across all components."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    total_cves = 0
    seen_ids = set()
    for comp in components:
        for cve in comp.cves:
            # Skip CVEs marked not_affected via VEX.
            if cve.get("vex_status") == "not_affected":
                continue
            total_cves += 1
            sev = (cve.get("severity") or "UNKNOWN").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["unknown"] += 1
            seen_ids.add(cve.get("id"))
    return {
        "total_components": len(components),
        "total_cves": total_cves,
        "unique_cves": len(seen_ids),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "unknown": counts["unknown"],
    }


def build_report(components: List[Component], sbom_source: str = "unknown") -> Dict:
    """Build the full report dict."""
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sbom_source": sbom_source,
        "summary": compute_summary(components),
        "components": [
            {
                "name": c.name,
                "version": c.version,
                "type": c.type,
                "vendor": c.vendor,
                "mpn": c.mpn,
                "part_ref": c.part_ref,
                "purl": c.purl,
                "cpe": c.cpe,
                "license": c.license,
                "evidence": c.evidence,
                "cves": c.cves,
            }
            for c in components
        ],
    }


def write_json_report(
    components: List[Component], output: str, sbom_source: str = "unknown"
) -> Dict:
    report = build_report(components, sbom_source)
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report
