"""Manual component entry from JSON or CSV.

JSON: [{"name": "openssl", "version": "1.1.1t", "type": "library", "vendor": "openssl"}, ...]
CSV:  header row with columns: name,version,vendor,type  (order-independent)
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import List

from ..core.component import Component
from ..utils.cpe import build_cpe
from ..utils.purl import build_purl


def _component_from_dict(d: dict) -> Component:
    name = (d.get("name") or "").strip()
    version = str(d.get("version") or "").strip()
    vendor = (d.get("vendor") or "").strip() or None
    ctype = (d.get("type") or "library").strip() or "library"
    comp = Component(
        name=name,
        version=version,
        type=ctype,
        vendor=vendor,
        cpe=d.get("cpe") or build_cpe(name, version, vendor, ctype),
        purl=d.get("purl") or build_purl(name, version, "generic"),
        license=d.get("license"),
        evidence="manual-entry",
    )
    return comp


def parse_json(text: str) -> List[Component]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("components", [data])
    return [_component_from_dict(d) for d in data if d.get("name")]


def parse_csv(text: str) -> List[Component]:
    reader = csv.DictReader(io.StringIO(text))
    comps = []
    for row in reader:
        # Normalize keys to lowercase.
        norm = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if norm.get("name"):
            comps.append(_component_from_dict(norm))
    return comps


def parse_table(text: str) -> List[Component]:
    """Parse a whitespace-aligned component table.

    Handles the output of other scanners (grype/trivy-style), e.g.::

        NAME     INSTALLED  TYPE    VULNERABILITY  SEVERITY ...
        busybox  1.36.1     binary  CVE-2022-48174 Critical ...

    Only the leading, stably-aligned columns (name / version / type) are read;
    duplicate rows (one per CVE) collapse to a single component. sbomx then runs
    its own CVE lookup against the extracted inventory.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    header = lines[0].lower().split()
    name_i = header.index("name") if "name" in header else 0
    ver_i = next(
        (header.index(k) for k in ("installed", "version", "ver") if k in header), 1
    )
    type_i = header.index("type") if "type" in header else None

    seen: dict[tuple, Component] = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) <= max(name_i, ver_i):
            continue
        name, version = parts[name_i], parts[ver_i]
        if not name or name.lower() == "name":
            continue
        raw_type = parts[type_i] if (type_i is not None and type_i < len(parts)) else ""
        ctype = "application" if raw_type.lower() in ("binary", "application", "app") else "library"
        key = (name, version)
        if key not in seen:
            seen[key] = _component_from_dict(
                {"name": name, "version": version, "vendor": name, "type": ctype}
            )
            seen[key].evidence = "scan-table-import"
    return list(seen.values())


def looks_like_table(text: str) -> bool:
    """True if the text's first line is a component-table header."""
    first = text.lstrip().splitlines()[0].lower().split() if text.strip() else []
    return "name" in first and any(k in first for k in ("installed", "version", "ver"))


def read_manual(path: str | Path, fmt: str | None = None) -> List[Component]:
    """Read a manual component list. Format auto-detected from extension if
    not given explicitly."""
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt is None:
        fmt = "csv" if path.suffix.lower() == ".csv" else "json"
    if fmt == "csv":
        return parse_csv(text)
    return parse_json(text)
