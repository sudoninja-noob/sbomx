"""Hardware BOM (HBOM) reader — parse EDA design-file BOM exports.

Reads a Bill of Materials exported from an EDA tool (KiCad, Altium, Eagle, or a
generic spreadsheet) into hardware :class:`Component` objects. Column names vary
between tools, so headers are matched fuzzily (case/spacing/punctuation-insensitive).

Each distinct part (by MPN, else by value+footprint) becomes one component of
type ``hardware``; reference designators are collected into ``part_ref`` and the
quantity is preserved in the evidence string. sbomx then maps each to a
``cpe:2.3:h:...`` string and runs the normal NVD CVE lookup.
"""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import List, Optional

from ..core.component import Component
from ..utils.cpe import build_cpe

# Header aliases → canonical field. Compared after normalization (lowercase,
# non-alphanumeric stripped).
_ALIASES = {
    "reference": "ref", "references": "ref", "designator": "ref",
    "designators": "ref", "refdes": "ref", "reference designator": "ref",
    "part": "ref",
    "mpn": "mpn", "manufacturerpartnumber": "mpn", "mfrpartnumber": "mpn",
    "mfrpart": "mpn", "partnumber": "mpn", "manufacturerpartno": "mpn",
    "mfgpartnumber": "mpn", "mpnno": "mpn",
    "manufacturer": "manufacturer", "mfr": "manufacturer", "mfg": "manufacturer",
    "manufacturername": "manufacturer", "vendor": "manufacturer", "brand": "manufacturer",
    "value": "value", "val": "value", "comment": "value", "component": "value",
    "quantity": "qty", "qty": "qty", "quantityper": "qty",
    "description": "description", "desc": "description",
    "footprint": "footprint", "package": "footprint", "packagereference": "footprint",
}


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (key or "").lower())


def _map_header(fieldnames) -> dict:
    """Map each raw CSV column to a canonical field name."""
    mapping = {}
    for raw in fieldnames or []:
        canon = _ALIASES.get(_norm(raw))
        if canon:
            mapping[raw] = canon
    return mapping


def looks_like_hbom(text: str) -> bool:
    """Heuristic: a delimited table whose header names a hardware BOM.

    Requires an MPN/part-number column, or a manufacturer column paired with a
    reference-designator column (which distinguishes it from a software CSV).
    """
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    delim = "\t" if "\t" in first and "," not in first else ","
    cols = {_ALIASES.get(_norm(c)) for c in first.split(delim)}
    if "mpn" in cols:
        return True
    return "manufacturer" in cols and "ref" in cols


def _build_component(rec: dict) -> Optional[Component]:
    mpn = (rec.get("mpn") or "").strip()
    value = (rec.get("value") or "").strip()
    manufacturer = (rec.get("manufacturer") or "").strip() or None
    description = (rec.get("description") or "").strip()
    footprint = (rec.get("footprint") or "").strip()

    # Component name: MPN preferred, else value, else description.
    name = mpn or value or description
    if not name:
        return None
    comp = Component(
        name=name,
        version="",  # discrete hardware parts generally carry no version
        type="hardware",
        vendor=manufacturer,
        mpn=mpn or None,
        part_ref=(rec.get("ref") or "").strip() or None,
        evidence="hbom:design-file",
    )
    # CPE product: the model. Use MPN when we have it, else the value.
    product = mpn or value or name
    comp.cpe = build_cpe(product, "", manufacturer, "hardware")
    if description or footprint:
        comp.license = None  # not applicable to hardware
    return comp


def _dedup_key(comp: Component):
    return (comp.mpn or comp.name, comp.vendor or "")


def parse_hbom_csv(text: str) -> List[Component]:
    # Detect delimiter (comma vs tab).
    sample = text.lstrip().splitlines()[0] if text.strip() else ""
    delim = "\t" if "\t" in sample and "," not in sample else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    header_map = _map_header(reader.fieldnames)

    merged: dict = {}
    for row in reader:
        rec = {}
        for raw, val in row.items():
            canon = header_map.get(raw)
            if canon:
                rec[canon] = val
        comp = _build_component(rec)
        if comp is None:
            continue
        key = _dedup_key(comp)
        if key in merged:
            # Merge reference designators of duplicate part rows.
            existing = merged[key]
            refs = ", ".join(
                r for r in (existing.part_ref, comp.part_ref) if r
            )
            existing.part_ref = refs or existing.part_ref
        else:
            merged[key] = comp
    return list(merged.values())


def parse_hbom_json(text: str) -> List[Component]:
    """Parse a JSON HBOM: a list of parts with mpn/manufacturer/value keys."""
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("parts") or data.get("components") or [data]
    comps = []
    for item in data:
        rec = {_ALIASES.get(_norm(k), k): v for k, v in item.items()}
        comp = _build_component(rec)
        if comp:
            comps.append(comp)
    return comps


def read_hbom(path: str | Path) -> List[Component]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json" or text.lstrip().startswith(("[", "{")):
        return parse_hbom_json(text)
    return parse_hbom_csv(text)
