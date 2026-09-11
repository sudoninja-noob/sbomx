"""Parse existing SBOM documents into the internal Component model.

Supports:
    - CycloneDX JSON
    - CycloneDX XML
    - SPDX JSON
    - SPDX tag-value (.spdx)

Format is auto-detected from content. Parsing is done directly (no heavy
library dependency) so it works in constrained/offline lab environments.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Tuple

from ..core.component import Component
from ..utils.cpe import build_cpe
from ..utils.purl import build_purl


class SbomParseError(ValueError):
    """Raised when an SBOM document cannot be parsed."""


def detect_format(text: str) -> str:
    """Return one of: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag."""
    stripped = text.lstrip()
    if stripped.startswith("<"):
        if "cyclonedx" in text[:2000].lower() or "<bom" in text[:2000].lower():
            return "cyclonedx-xml"
        return "cyclonedx-xml"  # only CycloneDX XML is supported here
    if stripped.startswith("{"):
        low = text[:4000].lower()
        if "bomformat" in low or "cyclonedx" in low:
            return "cyclonedx-json"
        if "spdxversion" in low or "spdxid" in low:
            return "spdx-json"
        # Heuristic fallback
        return "cyclonedx-json" if "components" in low else "spdx-json"
    # tag-value
    if "SPDXVersion:" in text or "PackageName:" in text:
        return "spdx-tag"
    raise SbomParseError("Unable to auto-detect SBOM format")


# --- CycloneDX ---------------------------------------------------------------

def _parse_cyclonedx_json(data: dict) -> Tuple[List[Component], Dict]:
    comps: List[Component] = []
    for c in data.get("components", []):
        comp = Component(
            name=c.get("name", "unknown"),
            version=str(c.get("version", "")),
            type=c.get("type", "library"),
            vendor=c.get("publisher") or c.get("group"),
            purl=c.get("purl"),
            license=_cdx_license(c.get("licenses")),
        )
        # CPE may be a direct field.
        if c.get("cpe"):
            comp.cpe = c["cpe"]
        for h in c.get("hashes", []) or []:
            if h.get("alg", "").upper() in ("SHA-256", "SHA256"):
                comp.sha256 = h.get("content")
        comp.evidence = "cyclonedx-import"
        comps.append(comp)
    meta = {
        "format": "CycloneDX",
        "spec_version": data.get("specVersion"),
        "serial_number": data.get("serialNumber"),
    }
    return comps, meta


def _cdx_license(licenses) -> str | None:
    if not licenses:
        return None
    first = licenses[0]
    if isinstance(first, dict):
        lic = first.get("license", first)
        return lic.get("id") or lic.get("name") or first.get("expression")
    return str(first)


def _parse_cyclonedx_xml(text: str) -> Tuple[List[Component], Dict]:
    # Strip namespaces for simpler traversal.
    text = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", text, count=0)
    root = ET.fromstring(text)
    comps: List[Component] = []
    for c in root.iter("component"):
        name = _xml_text(c, "name") or "unknown"
        version = _xml_text(c, "version") or ""
        comp = Component(
            name=name,
            version=version,
            type=c.get("type", "library"),
            vendor=_xml_text(c, "publisher") or _xml_text(c, "group"),
            purl=_xml_text(c, "purl"),
            license=_xml_text(c, "id") or _xml_text(c, "name"),
            cpe=_xml_text(c, "cpe"),
            evidence="cyclonedx-import",
        )
        comps.append(comp)
    meta = {"format": "CycloneDX", "spec_version": root.get("specVersion")}
    return comps, meta


def _xml_text(elem, tag) -> str | None:
    found = elem.find(tag)
    return found.text.strip() if found is not None and found.text else None


# --- SPDX --------------------------------------------------------------------

def _parse_spdx_json(data: dict) -> Tuple[List[Component], Dict]:
    comps: List[Component] = []
    for p in data.get("packages", []):
        comp = Component(
            name=p.get("name", "unknown"),
            version=str(p.get("versionInfo", "")),
            vendor=_spdx_supplier(p.get("supplier")),
            license=p.get("licenseConcluded") or p.get("licenseDeclared"),
            evidence="spdx-import",
        )
        for ref in p.get("externalRefs", []) or []:
            loc = ref.get("referenceLocator", "")
            if ref.get("referenceType") == "cpe23Type":
                comp.cpe = loc
            elif ref.get("referenceType") == "purl":
                comp.purl = loc
        for cks in p.get("checksums", []) or []:
            if cks.get("algorithm") == "SHA256":
                comp.sha256 = cks.get("checksumValue")
        comps.append(comp)
    meta = {
        "format": "SPDX",
        "spec_version": data.get("spdxVersion"),
        "namespace": data.get("documentNamespace"),
    }
    return comps, meta


def _spdx_supplier(value) -> str | None:
    if not value or value in ("NOASSERTION", "NONE"):
        return None
    # "Organization: Foo" / "Person: Bar"
    return value.split(":", 1)[-1].strip()


def _parse_spdx_tag(text: str) -> Tuple[List[Component], Dict]:
    comps: List[Component] = []
    current: dict = {}
    meta: dict = {"format": "SPDX"}

    def flush():
        if current.get("name"):
            comp = Component(
                name=current.get("name", "unknown"),
                version=current.get("version", ""),
                vendor=_spdx_supplier(current.get("supplier")),
                license=current.get("license"),
                cpe=current.get("cpe"),
                purl=current.get("purl"),
                sha256=current.get("sha256"),
                evidence="spdx-import",
            )
            comps.append(comp)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "SPDXVersion":
            meta["spec_version"] = val
        elif key == "DocumentNamespace":
            meta["namespace"] = val
        elif key == "PackageName":
            flush()
            current = {"name": val}
        elif key == "PackageVersion":
            current["version"] = val
        elif key == "PackageSupplier":
            current["supplier"] = val
        elif key in ("PackageLicenseConcluded", "PackageLicenseDeclared"):
            current.setdefault("license", val)
        elif key == "ExternalRef":
            # FORMAT: SECURITY cpe23Type <cpe>  or  PACKAGE-MANAGER purl <purl>
            parts = val.split()
            if len(parts) >= 3:
                rtype, locator = parts[1], parts[2]
                if rtype == "cpe23Type":
                    current["cpe"] = locator
                elif rtype == "purl":
                    current["purl"] = locator
        elif key == "PackageChecksum":
            if val.upper().startswith("SHA256"):
                current["sha256"] = val.split(":", 1)[-1].strip()
    flush()
    return comps, meta


# --- Public API --------------------------------------------------------------

def _enrich(comps: List[Component]) -> None:
    """Fill in missing cpe/purl so downstream CVE lookup has identifiers."""
    for c in comps:
        if not c.cpe:
            c.cpe = build_cpe(c.name, c.version, c.vendor, c.type)
        if not c.purl:
            c.purl = build_purl(c.name, c.version, "generic")


def parse_sbom_text(text: str) -> Tuple[List[Component], Dict]:
    fmt = detect_format(text)
    if fmt == "cyclonedx-json":
        comps, meta = _parse_cyclonedx_json(json.loads(text))
    elif fmt == "cyclonedx-xml":
        comps, meta = _parse_cyclonedx_xml(text)
    elif fmt == "spdx-json":
        comps, meta = _parse_spdx_json(json.loads(text))
    elif fmt == "spdx-tag":
        comps, meta = _parse_spdx_tag(text)
    else:  # pragma: no cover
        raise SbomParseError(f"Unsupported format: {fmt}")
    _enrich(comps)
    meta["detected_format"] = fmt
    return comps, meta


def read_sbom(path: str | Path) -> Tuple[List[Component], Dict]:
    """Read and parse an SBOM file, returning (components, metadata)."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    comps, meta = parse_sbom_text(text)
    meta["source_file"] = str(path)
    return comps, meta
