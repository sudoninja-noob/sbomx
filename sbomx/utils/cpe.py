"""CPE 2.3 string construction.

CPE 2.3 formatted string:
    cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:
            <sw_edition>:<target_sw>:<target_hw>:<other>
"""
from __future__ import annotations

from typing import Optional

# Component type -> CPE "part" code.
_PART_MAP = {
    "application": "a",
    "library": "a",
    "os": "o",
    "firmware": "o",
    "hardware": "h",
    "device": "h",
}


def _escape(value: str) -> str:
    """Escape characters that are special in CPE formatted strings."""
    out = []
    for ch in value:
        if ch in ":/?#[]@!$&'()*+,;= ":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out).lower()


def build_cpe(
    name: str,
    version: str,
    vendor: Optional[str] = None,
    comp_type: str = "library",
) -> str:
    """Build a best-effort CPE 2.3 string for a component.

    Vendor defaults to the product name when unknown (a common convention for
    single-project open-source software such as openssl/busybox).
    """
    part = _PART_MAP.get(comp_type, "a")
    product = _escape(name)
    vend = _escape(vendor) if vendor else product
    ver = _escape(version) if version else "*"
    # CPE 2.3 has 11 fields after "cpe:2.3:": part, vendor, product, version,
    # update, edition, language, sw_edition, target_sw, target_hw, other.
    # That's part + vendor + product + version + 7 wildcards.
    fields = [vend, product, ver] + ["*"] * 7
    return "cpe:2.3:" + part + ":" + ":".join(fields)
