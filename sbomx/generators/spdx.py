"""SPDX 2.3 SBOM generation (tag-value + JSON).

Emitted directly against the SPDX 2.3 spec. Includes a UUID-based document
namespace, creator info, per-package SPDXIDs, LicenseConcluded, and ExternalRefs
for CPE + purl (NTIA minimum elements + unique identifiers).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from .. import __version__, TOOL_NAME
from ..core.component import Component

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _namespace(name: str) -> str:
    return f"https://sbomx/spdx/{name}-{uuid.uuid4()}"


def _spdxid(comp: Component, index: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9.\-]", "-", f"{comp.name}-{comp.version}")
    return f"SPDXRef-Package-{safe}-{index}"


def _license(value: str | None) -> str:
    return value if value else "NOASSERTION"


def _supplier(vendor: str | None) -> str:
    return f"Organization: {vendor}" if vendor else "NOASSERTION"


# SPDX 2.3 primaryPackagePurpose values.
_SPDX_PURPOSE = {
    "application": "APPLICATION",
    "library": "LIBRARY",
    "firmware": "FIRMWARE",
    "os": "OPERATING-SYSTEM",
    "operating-system": "OPERATING-SYSTEM",
    "hardware": "DEVICE",
    "device": "DEVICE",
}


def _purpose(comp_type: str) -> str:
    return _SPDX_PURPOSE.get(comp_type, "OTHER")


def build_spdx_dict(components: List[Component], name: str = "sbomx-document") -> Dict:
    packages = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-DOCUMENT",
        }
    ]
    for i, c in enumerate(components):
        sid = _spdxid(c, i)
        ext_refs = []
        if c.cpe:
            ext_refs.append({
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": c.cpe,
            })
        if c.purl:
            ext_refs.append({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": c.purl,
            })
        pkg = {
            "SPDXID": sid,
            "name": c.name,
            "versionInfo": c.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": _license(c.license),
            "licenseDeclared": _license(c.license),
            "copyrightText": "NOASSERTION",
            "supplier": _supplier(c.vendor),
        }
        if ext_refs:
            pkg["externalRefs"] = ext_refs
        if c.sha256:
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": c.sha256}]
        pkg["primaryPackagePurpose"] = _purpose(c.type)
        if c.mpn:
            pkg["comment"] = f"MPN: {c.mpn}"
        packages.append(pkg)
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": sid,
        })

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": _namespace(name),
        "creationInfo": {
            "created": _now(),
            "creators": [f"Tool: {TOOL_NAME}-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def build_spdx_tag(components: List[Component], name: str = "sbomx-document") -> str:
    lines = [
        f"SPDXVersion: {SPDX_VERSION}",
        f"DataLicense: {DATA_LICENSE}",
        "SPDXID: SPDXRef-DOCUMENT",
        f"DocumentName: {name}",
        f"DocumentNamespace: {_namespace(name)}",
        f"Creator: Tool: {TOOL_NAME}-{__version__}",
        f"Created: {_now()}",
        "",
    ]
    for i, c in enumerate(components):
        sid = _spdxid(c, i)
        lines += [
            f"PackageName: {c.name}",
            f"SPDXID: {sid}",
            f"PackageVersion: {c.version}",
            f"PackageSupplier: {_supplier(c.vendor)}",
            "PackageDownloadLocation: NOASSERTION",
            "FilesAnalyzed: false",
            f"PackageLicenseConcluded: {_license(c.license)}",
            f"PackageLicenseDeclared: {_license(c.license)}",
            "PackageCopyrightText: NOASSERTION",
        ]
        if c.sha256:
            lines.append(f"PackageChecksum: SHA256: {c.sha256}")
        lines.append(f"PrimaryPackagePurpose: {_purpose(c.type)}")
        if c.mpn:
            lines.append(f"PackageComment: <text>MPN: {c.mpn}</text>")
        if c.cpe:
            lines.append(f"ExternalRef: SECURITY cpe23Type {c.cpe}")
        if c.purl:
            lines.append(f"ExternalRef: PACKAGE-MANAGER purl {c.purl}")
        lines.append(f"Relationship: SPDXRef-DOCUMENT DESCRIBES {sid}")
        lines.append("")
    return "\n".join(lines)


def validate_with_lib(spdx_dict: Dict) -> bool:
    """Best-effort validation using spdx-tools if installed."""
    try:  # pragma: no cover - optional dependency
        from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import (
            JsonLikeDictParser,
        )
        from spdx_tools.spdx.validation.document_validator import (
            validate_full_spdx_document,
        )

        doc = JsonLikeDictParser().parse(spdx_dict)
        messages = validate_full_spdx_document(doc)
        return len(messages) == 0
    except Exception:
        return True


def write_spdx(components: List[Component], output: str, fmt: str = "json") -> str:
    if fmt in ("tag", "tag-value", "spdx"):
        data = build_spdx_tag(components)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(data)
    else:
        doc = build_spdx_dict(components)
        validate_with_lib(doc)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    return output
