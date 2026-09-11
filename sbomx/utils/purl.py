"""Package URL (purl) construction.

Spec: https://github.com/package-url/purl-spec
    pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import quote

# Map our component/ecosystem hints to purl types.
ECOSYSTEM_TO_PURL = {
    "pypi": "pypi",
    "pip": "pypi",
    "npm": "npm",
    "maven": "maven",
    "gradle": "maven",
    "go": "golang",
    "cargo": "cargo",
    "generic": "generic",
}


def _enc(value: str) -> str:
    return quote(value, safe="")


def build_purl(
    name: str,
    version: str,
    purl_type: str = "generic",
    namespace: Optional[str] = None,
) -> str:
    """Build a purl string. Falls back to the 'generic' type."""
    ptype = ECOSYSTEM_TO_PURL.get(purl_type.lower(), purl_type.lower() or "generic")
    parts = ["pkg:", ptype, "/"]
    if namespace:
        parts.append(_enc(namespace) + "/")
    parts.append(_enc(name))
    if version:
        parts.append("@" + _enc(version))
    return "".join(parts)
