"""Main orchestrator: turn any input into components, optionally enrich with
CVEs, and drive the generators / reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..cve.aggregator import CveAggregator
from ..utils.logging import get_logger
from .component import Component
from .config import Settings

log = get_logger("sbomx.scanner")


def detect_input_kind(path: str | Path) -> str:
    """Classify an input into: directory | binary | sbom | manifest | manual."""
    p = Path(path)
    if p.is_dir():
        return "directory"
    name = p.name.lower()
    manifest_names = {
        "requirements.txt", "package.json", "package-lock.json", "pom.xml",
        "go.sum", "go.mod", "cargo.toml", "cargo.lock",
    }
    if name in manifest_names or name.endswith("requirements.txt"):
        return "manifest"
    suffix = p.suffix.lower()
    if suffix == ".csv":
        return "manual"
    if suffix in (".json", ".xml", ".spdx"):
        # Peek to distinguish SBOM from a manual component list.
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:2000].lower()
        except OSError:
            head = ""
        if any(k in head for k in ("bomformat", "spdxversion", "spdxid", "cyclonedx", "<bom")):
            return "sbom"
        if suffix == ".json":
            return "manual"
        return "sbom"
    # Unknown extension: sniff for a binary (ELF/PE/Mach-O) → binary scan.
    from ..inputs.binary_scanner import _detect_binary_type

    if _detect_binary_type(p) is not None:
        return "binary"

    # Text file: a scanner-style component table (NAME / INSTALLED|VERSION ...)?
    try:
        head = p.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        head = ""
    from ..inputs.manual_entry import looks_like_table

    if looks_like_table(head):
        return "table"
    return "sbom"


def load_components(
    path: str | Path,
    kind: Optional[str] = None,
    include_self: bool = False,
) -> Tuple[List[Component], Dict]:
    """Load components from any supported input. Returns (components, meta)."""
    kind = kind or detect_input_kind(path)
    meta: Dict = {"input_kind": kind, "source_file": str(path)}

    if kind in ("directory", "binary"):
        from ..inputs.binary_scanner import scan_directory

        comps = scan_directory(path, include_self=include_self)
    elif kind == "sbom":
        from ..inputs.sbom_reader import read_sbom

        comps, sbom_meta = read_sbom(path)
        meta.update(sbom_meta)
    elif kind == "manifest":
        from ..inputs.manifest_reader import read_manifest

        comps = read_manifest(path)
    elif kind == "manual":
        from ..inputs.manual_entry import read_manual

        comps = read_manual(path)
    elif kind == "table":
        from ..inputs.manual_entry import parse_table
        from pathlib import Path as _P

        comps = parse_table(_P(path).read_text(encoding="utf-8", errors="replace"))
    else:  # pragma: no cover
        raise ValueError(f"Unknown input kind: {kind}")

    log.info("components_loaded", kind=kind, count=len(comps))
    return comps, meta


def enrich_with_cves(
    components: List[Component],
    settings: Optional[Settings] = None,
    progress=None,
    sources: str = "all",
) -> List[Component]:
    """Run CVE lookups against all components.

    :param sources: "all" | "nvd" | "osv" — which CVE databases to query.
    """
    settings = settings or Settings.load()
    aggregator = CveAggregator(settings, sources=sources)
    return aggregator.enrich(components, progress=progress)
