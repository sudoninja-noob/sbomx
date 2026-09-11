"""Firmware binary / rootfs directory scanner.

Walks a directory tree, identifies executables and shared libraries, and
extracts component evidence. Uses lief + python-magic when available, and
always falls back to pure-Python magic-number detection and regex string
scanning so it runs on any platform (including Windows lab machines without
libmagic installed).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from ..core.component import Component
from ..utils.cpe import build_cpe
from ..utils.hash import sha256_file
from ..utils.logging import get_logger
from ..utils.purl import build_purl

log = get_logger("sbomx.binary")

# Optional deps -------------------------------------------------------------
try:
    import lief  # type: ignore

    _HAVE_LIEF = True
except Exception:  # pragma: no cover
    _HAVE_LIEF = False

try:
    import magic  # type: ignore

    _HAVE_MAGIC = True
except Exception:  # pragma: no cover
    _HAVE_MAGIC = False


# Known library version string patterns. Map: regex -> (name, vendor).
_VERSION_PATTERNS = [
    (re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"), "openssl", "openssl"),
    (re.compile(rb"openssl[/-](\d+\.\d+\.\d+[a-z]?)"), "openssl", "openssl"),
    (re.compile(rb"BusyBox\s+v?(\d+\.\d+\.\d+)"), "busybox", "busybox"),
    (re.compile(rb"zlib\s+(\d+\.\d+\.\d+)"), "zlib", "zlib"),
    (re.compile(rb"libcurl[/-](\d+\.\d+\.\d+)"), "curl", "haxx"),
    (re.compile(rb"curl\s+(\d+\.\d+\.\d+)"), "curl", "haxx"),
    (re.compile(rb"GNU C Library.*release version (\d+\.\d+)"), "glibc", "gnu"),
    (re.compile(rb"Dropbear\s+v?(\d+\.\d+)"), "dropbear", "dropbear"),
    (re.compile(rb"OpenSSH[_-](\d+\.\d+)"), "openssh", "openbsd"),
    (re.compile(rb"Lua\s+(\d+\.\d+\.\d+)"), "lua", "lua"),
    (re.compile(rb"SQLite\s+(\d+\.\d+\.\d+)"), "sqlite", "sqlite"),
    (re.compile(rb"U-Boot\s+(\d{4}\.\d+)"), "u-boot", "denx"),
    (re.compile(rb"Linux version (\d+\.\d+\.\d+)"), "linux_kernel", "linux"),
]

# Magic numbers for binary detection without libmagic.
_MAGIC = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xca\xfe\xba\xbe": "Mach-O",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
}

_MAX_READ = 8 * 1024 * 1024  # cap string-scan reads at 8 MiB per file


def _detect_binary_type(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for magic_bytes, label in _MAGIC.items():
        if head.startswith(magic_bytes):
            return label
    if _HAVE_MAGIC:
        try:
            desc = magic.from_file(str(path))
            if "ELF" in desc:
                return "ELF"
            if "PE32" in desc or "MS-DOS" in desc:
                return "PE"
        except Exception:
            pass
    return None


def _scan_strings(path: Path) -> List[Component]:
    """Regex-scan a binary for known library version strings."""
    found: List[Component] = []
    seen: set[tuple] = set()
    try:
        data = path.read_bytes()[:_MAX_READ]
    except OSError:
        return found
    for pattern, name, vendor in _VERSION_PATTERNS:
        for m in pattern.finditer(data):
            version = m.group(1).decode("ascii", "replace")
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            found.append(
                Component(
                    name=name,
                    version=version,
                    type="os" if name in ("linux_kernel", "u-boot") else "library",
                    vendor=vendor,
                    cpe=build_cpe(name, version, vendor),
                    purl=build_purl(name, version, "generic"),
                    source_file=str(path),
                    evidence=f"string-match:{pattern.pattern.decode('ascii','replace')[:40]}",
                )
            )
    return found


def _lief_component(path: Path, btype: str) -> Optional[Component]:
    """Use lief to record the binary itself as a firmware/application component."""
    if not _HAVE_LIEF:  # pragma: no cover
        return None
    try:
        binary = lief.parse(str(path))
        if binary is None:
            return None
        build_id = None
        try:
            note = binary.get_section(".note.gnu.build-id")
            if note is not None:
                build_id = bytes(note.content).hex()[:40]
        except Exception:
            pass
        return Component(
            name=path.name,
            version=build_id or "unknown",
            type="firmware",
            cpe=None,
            source_file=str(path),
            evidence=f"lief:{btype}",
        )
    except Exception:  # pragma: no cover
        return None


def scan_directory(root: str | Path, include_self: bool = False) -> List[Component]:
    """Walk a directory and return detected components.

    :param include_self: also emit a component for each binary file itself
                         (useful for firmware inventory).
    """
    root = Path(root)
    components: List[Component] = []
    dedup: dict[tuple, Component] = {}

    targets: List[Path]
    if root.is_file():
        targets = [root]
    else:
        targets = [p for p in root.rglob("*") if p.is_file()]

    for path in targets:
        btype = _detect_binary_type(path)
        if btype is None:
            continue
        log.debug("binary_detected", file=str(path), type=btype)
        for comp in _scan_strings(path):
            key = (comp.name, comp.version)
            if key not in dedup:
                comp.sha256 = _safe_hash(path)
                dedup[key] = comp
        if include_self:
            self_comp = _lief_component(path, btype)
            if self_comp:
                self_comp.sha256 = _safe_hash(path)
                components.append(self_comp)

    components.extend(dedup.values())
    return components


def _safe_hash(path: Path) -> Optional[str]:
    try:
        return sha256_file(path)
    except OSError:
        return None
