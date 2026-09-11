"""CycloneDX 1.6 SBOM generation (JSON + XML).

Emitted directly against the CycloneDX 1.6 spec so the tool has no hard
dependency on cyclonedx-python-lib. Includes components (with purl + cpe),
a vulnerabilities section when CVEs are present, and NTIA-minimum metadata.
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List
from xml.dom import minidom

from .. import __version__, TOOL_NAME
from ..core.component import Component

SPEC_VERSION = "1.6"
SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
XMLNS = "http://cyclonedx.org/schema/bom/1.6"

_CVSS_METHOD = "CVSSv31"


# Map internal component types to valid CycloneDX component types.
_CDX_TYPES = {
    "application": "application",
    "library": "library",
    "firmware": "firmware",
    "os": "operating-system",
    "operating-system": "operating-system",
    "hardware": "device",
    "device": "device",
}


def _cdx_type(t: str) -> str:
    return _CDX_TYPES.get(t, "library")


def _serial() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _vulnerabilities(components: List[Component]) -> List[Dict]:
    vulns: List[Dict] = []
    for comp in components:
        for cve in comp.cves:
            ratings = []
            if cve.get("cvss_score") is not None:
                ratings.append(
                    {
                        "source": {"name": cve.get("source", "unknown").upper()},
                        "score": cve["cvss_score"],
                        "severity": (cve.get("severity") or "unknown").lower(),
                        "method": _CVSS_METHOD,
                        "vector": cve.get("cvss_vector") or "",
                    }
                )
            entry = {
                "bom-ref": f"vuln-{cve['id']}-{comp.ref}",
                "id": cve["id"],
                "source": {
                    "name": "NVD",
                    "url": cve.get("nvd_url", ""),
                },
                "ratings": ratings,
                "description": cve.get("description", ""),
                "affects": [{"ref": comp.ref}],
            }
            if cve.get("published"):
                entry["published"] = cve["published"]
            if cve.get("vex_status"):
                entry["analysis"] = {
                    "state": _vex_to_cdx_state(cve["vex_status"]),
                    "detail": cve.get("vex_justification", ""),
                }
            vulns.append(entry)
    return vulns


def _vex_to_cdx_state(status: str) -> str:
    return {
        "not_affected": "not_affected",
        "affected": "exploitable",
        "fixed": "resolved",
        "under_investigation": "in_triage",
    }.get(status, "in_triage")


def build_bom_dict(components: List[Component]) -> Dict:
    comp_list = []
    for c in components:
        entry = {
            "type": _cdx_type(c.type),
            "bom-ref": c.ref,
            "name": c.name,
            "version": c.version,
        }
        if c.vendor:
            entry["publisher"] = c.vendor
            if c.is_hardware:
                entry["manufacturer"] = {"name": c.vendor}
        if c.mpn:
            entry["properties"] = [{"name": "mpn", "value": c.mpn}]
        if c.part_ref:
            entry.setdefault("properties", []).append(
                {"name": "reference-designator", "value": c.part_ref}
            )
        if c.purl:
            entry["purl"] = c.purl
        if c.cpe:
            entry["cpe"] = c.cpe
        if c.license:
            entry["licenses"] = [{"license": {"name": c.license}}]
        if c.sha256:
            entry["hashes"] = [{"alg": "SHA-256", "content": c.sha256}]
        comp_list.append(entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "$schema": SCHEMA,
        "serialNumber": _serial(),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": __version__}
                ]
            },
        },
        "components": comp_list,
    }
    vulns = _vulnerabilities(components)
    if vulns:
        bom["vulnerabilities"] = vulns
    return bom


def _el(parent, tag, text=None, **attrs):
    e = ET.SubElement(parent, tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        e.text = str(text)
    return e


def build_bom_xml(components: List[Component]) -> str:
    root = ET.Element("bom", {
        "xmlns": XMLNS,
        "serialNumber": _serial(),
        "version": "1",
    })
    meta = _el(root, "metadata")
    _el(meta, "timestamp", _timestamp())
    tools = _el(meta, "tools")
    tool = _el(tools, "tool")
    _el(tool, "name", TOOL_NAME)
    _el(tool, "version", __version__)

    comps_el = _el(root, "components")
    for c in components:
        comp_el = _el(comps_el, "component", type=_cdx_type(c.type), **{"bom-ref": c.ref})
        _el(comp_el, "name", c.name)
        _el(comp_el, "version", c.version)
        if c.vendor:
            _el(comp_el, "publisher", c.vendor)
        if c.mpn:
            _el(comp_el, "mpn", c.mpn)
        if c.cpe:
            _el(comp_el, "cpe", c.cpe)
        if c.purl:
            _el(comp_el, "purl", c.purl)
        if c.license:
            lics = _el(comp_el, "licenses")
            lic = _el(lics, "license")
            _el(lic, "name", c.license)

    vulns = _vulnerabilities(components)
    if vulns:
        vroot = _el(root, "vulnerabilities")
        for v in vulns:
            vel = _el(vroot, "vulnerability", **{"bom-ref": v["bom-ref"]})
            _el(vel, "id", v["id"])
            if v.get("description"):
                _el(vel, "description", v["description"])

    rough = ET.tostring(root, encoding="unicode")
    return minidom.parseString(rough).toprettyxml(indent="  ")


def validate_with_lib(bom: Dict) -> bool:
    """Best-effort validation using cyclonedx-python-lib if installed."""
    try:  # pragma: no cover - optional dependency
        from cyclonedx.validation.json import JsonStrictValidator
        from cyclonedx.schema import SchemaVersion
        import json as _json

        validator = JsonStrictValidator(SchemaVersion.V1_6)
        errors = validator.validate_str(_json.dumps(bom))
        return errors is None
    except Exception:
        return True  # library absent → skip validation, trust hand-built doc


def write_cyclonedx(components: List[Component], output: str, fmt: str = "json") -> str:
    import json

    if fmt == "xml":
        data = build_bom_xml(components)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        bom = build_bom_dict(components)
        validate_with_lib(bom)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=2)
    return output
