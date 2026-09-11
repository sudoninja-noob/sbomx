"""VEX (Vulnerability Exploitability eXchange) support.

Two capabilities:
  1. apply_vex_input()  - read a VEX JSON file and annotate components' CVEs
                          with a vex_status (e.g. not_affected), so reports and
                          summaries can suppress non-exploitable findings.
  2. build_vex_document() - emit a CycloneDX-style VEX document describing the
                          analysis state of each vulnerability.

VEX input format (simple, CSAF/OpenVEX-compatible subset):
  {
    "statements": [
      {"vulnerability": "CVE-2023-0464", "status": "not_affected",
       "justification": "vulnerable_code_not_in_execute_path",
       "component": "openssl"}      # component optional; omit to match all
    ]
  }
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .. import __version__, TOOL_NAME
from ..core.component import Component

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def load_vex_statements(path: str | Path) -> List[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    stmts = data.get("statements") or data.get("vulnerabilities") or []
    out = []
    for s in stmts:
        vuln = s.get("vulnerability") or s.get("id") or s.get("cve")
        status = s.get("status")
        if vuln and status in VALID_STATUSES:
            out.append({
                "vulnerability": vuln,
                "status": status,
                "justification": s.get("justification", ""),
                "component": s.get("component"),
            })
    return out


def apply_vex_input(components: List[Component], vex_path: str | Path) -> int:
    """Annotate matching CVEs with their VEX status. Returns count annotated."""
    statements = load_vex_statements(vex_path)
    applied = 0
    for comp in components:
        for cve in comp.cves:
            for stmt in statements:
                if cve.get("id") != stmt["vulnerability"]:
                    continue
                if stmt["component"] and stmt["component"].lower() != comp.name.lower():
                    continue
                cve["vex_status"] = stmt["status"]
                cve["vex_justification"] = stmt["justification"]
                applied += 1
    return applied


def build_vex_document(components: List[Component]) -> Dict:
    """Build a CycloneDX 1.6 VEX document from annotated components."""
    vulns = []
    for comp in components:
        for cve in comp.cves:
            status = cve.get("vex_status") or "under_investigation"
            vulns.append({
                "id": cve["id"],
                "source": {"name": "NVD", "url": cve.get("nvd_url", "")},
                "analysis": {
                    "state": {
                        "not_affected": "not_affected",
                        "affected": "exploitable",
                        "fixed": "resolved",
                        "under_investigation": "in_triage",
                    }.get(status, "in_triage"),
                    "detail": cve.get("vex_justification", ""),
                },
                "affects": [{"ref": comp.ref}],
            })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": __version__}]},
        },
        "vulnerabilities": vulns,
    }


def write_vex(components: List[Component], output: str) -> str:
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(build_vex_document(components), fh, indent=2)
    return output
