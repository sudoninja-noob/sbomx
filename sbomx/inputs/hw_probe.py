"""Firmware-inferred hardware inventory.

Extracts hardware components from artifacts pulled off an embedded device when
no schematic/BOM is available:

    - Device Tree source (.dts, or `dtc`-decompiled .dtb): `compatible` and
      `model` properties name the SoC and on-board peripherals.
    - `lspci` / `lspci -nn` output: PCI devices with vendor:device IDs.
    - `lsusb` output: USB devices with idVendor:idProduct.
    - `/proc/cpuinfo`: CPU model / SoC hardware line.

Each device becomes a hardware :class:`Component`. The sub-format is
auto-detected from the text content.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from ..core.component import Component
from ..utils.cpe import build_cpe

# --- Device Tree -------------------------------------------------------------

# A `compatible` property may list several strings: compatible = "a,b", "c,d";
_COMPAT_RE = re.compile(r'compatible\s*=\s*([^;]+);')
_STRING_RE = re.compile(r'"([^"]+)"')
_MODEL_RE = re.compile(r'model\s*=\s*"([^"]+)"')


def _mk(name: str, vendor: Optional[str], evidence: str, model: Optional[str] = None) -> Component:
    comp = Component(
        name=name,
        version="",
        type="hardware",
        vendor=vendor,
        evidence=evidence,
    )
    comp.cpe = build_cpe(model or name, "", vendor, "hardware")
    return comp


def parse_device_tree(text: str) -> List[Component]:
    comps: List[Component] = []
    seen: set = set()

    # Board-level model (e.g. "Raspberry Pi 4 Model B").
    m = _MODEL_RE.search(text)
    if m:
        model = m.group(1)
        comps.append(_mk(model, None, "hwprobe:devicetree:model"))
        seen.add(model.lower())

    # Each `compatible` property lists one or more "vendor,part" strings.
    # (In a raw .dtb these are NUL-joined; in .dts they are quoted, comma-separated.)
    for match in _COMPAT_RE.finditer(text):
        raw = match.group(1)
        tokens = _STRING_RE.findall(raw) or raw.split("\x00")
        for token in tokens:
            token = token.strip()
            if not token or token in seen or token == "simple-bus":
                continue
            seen.add(token)
            if "," in token:
                vendor, part = token.split(",", 1)
            else:
                vendor, part = None, token
            comps.append(_mk(part, vendor, "hwprobe:devicetree:compatible", model=part))
    return comps


# --- lspci -------------------------------------------------------------------

# 00:1f.3 Audio device: Intel Corporation Sunrise Point-LP HD Audio [8086:9d71]
_LSPCI_RE = re.compile(
    r"^\S+\s+[^:]+:\s+(?P<desc>.+?)(?:\s+\[(?P<ids>[0-9a-fA-F]{4}:[0-9a-fA-F]{4})\])?\s*$"
)


def parse_lspci(text: str) -> List[Component]:
    comps: List[Component] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or not re.match(r"^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.", line):
            continue
        m = _LSPCI_RE.match(line)
        if not m:
            continue
        desc = m.group("desc").strip()
        vendor = _leading_vendor(desc)
        comp = _mk(desc, vendor, "hwprobe:lspci", model=desc)
        if m.group("ids"):
            comp.mpn = m.group("ids")  # PCI vendor:device id as the part id
        comps.append(comp)
    return comps


# --- lsusb -------------------------------------------------------------------

# Bus 001 Device 002: ID 8087:0a2b Intel Corp. Bluetooth
_LSUSB_RE = re.compile(
    r"^Bus\s+\d+\s+Device\s+\d+:\s+ID\s+(?P<ids>[0-9a-fA-F]{4}:[0-9a-fA-F]{4})\s*(?P<desc>.*)$"
)


def parse_lsusb(text: str) -> List[Component]:
    comps: List[Component] = []
    for line in text.splitlines():
        m = _LSUSB_RE.match(line.strip())
        if not m:
            continue
        desc = m.group("desc").strip() or f"USB device {m.group('ids')}"
        vendor = _leading_vendor(desc)
        comp = _mk(desc, vendor, "hwprobe:lsusb", model=desc)
        comp.mpn = m.group("ids")
        comps.append(comp)
    return comps


# --- /proc/cpuinfo -----------------------------------------------------------

def parse_cpuinfo(text: str) -> List[Component]:
    comps: List[Component] = []
    model_name = None
    hardware = None
    vendor = None
    for line in text.splitlines():
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "model name" and not model_name:
            model_name = val
        elif key == "hardware" and not hardware:
            hardware = val
        elif key == "vendor_id" and not vendor:
            vendor = val
    if model_name:
        comps.append(_mk(model_name, vendor, "hwprobe:cpuinfo:cpu", model=model_name))
    if hardware and hardware != model_name:
        comps.append(_mk(hardware, None, "hwprobe:cpuinfo:soc", model=hardware))
    return comps


# --- vendor normalization ----------------------------------------------------

_KNOWN_VENDORS = {
    "intel": "intel", "amd": "amd", "broadcom": "broadcom", "qualcomm": "qualcomm",
    "realtek": "realtek", "nvidia": "nvidia", "samsung": "samsung", "nxp": "nxp",
    "texas": "ti", "mediatek": "mediatek", "marvell": "marvell", "atheros": "atheros",
    "renesas": "renesas", "microchip": "microchip", "stmicroelectronics": "st",
}


def _leading_vendor(desc: str) -> Optional[str]:
    low = desc.lower()
    for needle, canon in _KNOWN_VENDORS.items():
        if needle in low:
            return canon
    # Fall back to the first word if it looks like a company name.
    first = desc.split()[0] if desc.split() else ""
    return first.lower() if first and first[0].isalpha() else None


# --- detection + dispatch ----------------------------------------------------

def detect_probe_format(text: str) -> Optional[str]:
    head = text[:4000]
    if _COMPAT_RE.search(head) or _MODEL_RE.search(head):
        return "devicetree"
    if re.search(r"^Bus\s+\d+\s+Device\s+\d+:\s+ID\s+[0-9a-fA-F]{4}:", head, re.M):
        return "lsusb"
    if re.search(r"^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.\d", head, re.M):
        return "lspci"
    if re.search(r"^\s*(model name|processor|Hardware)\s*:", head, re.M):
        return "cpuinfo"
    return None


def looks_like_hwprobe(text: str) -> bool:
    return detect_probe_format(text) is not None


_PARSERS = {
    "devicetree": parse_device_tree,
    "lspci": parse_lspci,
    "lsusb": parse_lsusb,
    "cpuinfo": parse_cpuinfo,
}


def read_hwprobe(path_or_text, is_text: bool = False) -> List[Component]:
    """Parse a hardware-probe artifact. Pass is_text=True to treat the argument
    as raw text rather than a path."""
    text = path_or_text if is_text else Path(path_or_text).read_text(
        encoding="utf-8", errors="replace"
    )
    fmt = detect_probe_format(text)
    if fmt is None:
        return []
    return _PARSERS[fmt](text)
