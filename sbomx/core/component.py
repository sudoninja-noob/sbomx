"""Core component and CVE data models.

The :class:`Component` is the normalized internal representation that every
input source produces and every generator/report consumes.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


# --- Severity helpers --------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def severity_from_score(score: Optional[float]) -> str:
    """Map a CVSS v3.1 base score to a qualitative severity band."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


@dataclass
class CVE:
    """A single vulnerability record, normalized across sources."""

    id: str
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str = ""
    published: Optional[str] = None
    source: str = "unknown"  # nvd | osv | ...
    references: List[str] = field(default_factory=list)
    nvd_url: Optional[str] = None
    # VEX state: affected | not_affected | fixed | under_investigation
    vex_status: Optional[str] = None
    vex_justification: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Component:
    """Normalized software component used throughout sbomx."""

    name: str
    version: str
    type: str = "library"  # library | application | firmware | os | hardware | device
    vendor: Optional[str] = None  # supplier / manufacturer
    cpe: Optional[str] = None  # CPE 2.3 string
    purl: Optional[str] = None  # pkg:type/namespace/name@version
    license: Optional[str] = None
    sha256: Optional[str] = None
    source_file: Optional[str] = None
    evidence: Optional[str] = None  # how it was detected
    # Hardware-specific identifiers (populated for HBOM / hardware components).
    mpn: Optional[str] = None  # manufacturer part number
    part_ref: Optional[str] = None  # PCB reference designator(s), e.g. "U1, U2"
    cves: List[dict] = field(default_factory=list)

    HARDWARE_TYPES = ("hardware", "device")

    @property
    def is_hardware(self) -> bool:
        return self.type in self.HARDWARE_TYPES

    # Stable identifier for SBOM references (SPDXID / bom-ref).
    @property
    def ref(self) -> str:
        safe = f"{self.name}-{self.version}".replace(" ", "_")
        return safe

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def add_cve(self, cve: "CVE | dict") -> None:
        self.cves.append(cve.to_dict() if isinstance(cve, CVE) else cve)
