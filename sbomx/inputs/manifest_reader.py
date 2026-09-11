"""Parse package manifest / lock files into components.

Supported:
    - pip:   requirements.txt
    - npm:   package.json, package-lock.json
    - maven: pom.xml
    - go:    go.sum, go.mod
    - cargo: Cargo.toml, Cargo.lock
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from ..core.component import Component
from ..utils.cpe import build_cpe
from ..utils.purl import build_purl

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=)?\s*([0-9][\w.\-]*)?")


def _mk(name, version, ecosystem, namespace=None, vendor=None) -> Component:
    return Component(
        name=name,
        version=version or "",
        type="library",
        vendor=vendor,
        purl=build_purl(name, version or "", ecosystem, namespace),
        cpe=build_cpe(name, version or "", vendor),
        evidence=f"manifest:{ecosystem}",
    )


def parse_requirements(text: str) -> List[Component]:
    comps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";")[0].split("#")[0].strip()
        m = _REQ_LINE.match(line)
        if m and m.group(1):
            comps.append(_mk(m.group(1), m.group(2) or "", "pypi"))
    return comps


def parse_package_json(text: str) -> List[Component]:
    data = json.loads(text)
    comps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(ver))
            namespace = None
            pkg = name
            if name.startswith("@") and "/" in name:
                namespace, pkg = name.split("/", 1)
            comps.append(_mk(pkg, version, "npm", namespace))
    return comps


def parse_package_lock(text: str) -> List[Component]:
    data = json.loads(text)
    comps = []
    packages = data.get("packages") or {}
    if packages:
        for path, info in packages.items():
            if not path or not info.get("version"):
                continue
            name = path.split("node_modules/")[-1]
            comps.append(_mk(name, info["version"], "npm"))
        return comps
    for name, info in (data.get("dependencies") or {}).items():
        comps.append(_mk(name, info.get("version", ""), "npm"))
    return comps


def parse_pom(text: str) -> List[Component]:
    text = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", text)
    root = ET.fromstring(text)
    comps = []
    for dep in root.iter("dependency"):
        gid = dep.findtext("groupId") or ""
        aid = dep.findtext("artifactId") or ""
        ver = dep.findtext("version") or ""
        if aid:
            comps.append(_mk(aid, ver, "maven", namespace=gid or None, vendor=gid or None))
    return comps


def parse_go_sum(text: str) -> List[Component]:
    comps, seen = [], set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1].replace("/go.mod", "")
            key = (module, version)
            if key in seen:
                continue
            seen.add(key)
            ns, _, name = module.rpartition("/")
            comps.append(_mk(name or module, version.lstrip("v"), "golang", namespace=ns or None))
    return comps


def parse_go_mod(text: str) -> List[Component]:
    comps = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"(?:require\s+)?([^\s]+)\s+v([\w.\-]+)", line)
        if m and "/" in m.group(1):
            module = m.group(1)
            ns, _, name = module.rpartition("/")
            comps.append(_mk(name or module, m.group(2), "golang", namespace=ns or None))
    return comps


def parse_cargo_toml(text: str) -> List[Component]:
    comps, in_deps = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_deps = line in ("[dependencies]", "[dev-dependencies]")
            continue
        if in_deps and "=" in line:
            name, _, rest = line.partition("=")
            name = name.strip()
            vm = re.search(r'"([\d][\w.\-]*)"', rest)
            if not vm:
                vm = re.search(r'version\s*=\s*"([\d][\w.\-]*)"', rest)
            comps.append(_mk(name, vm.group(1) if vm else "", "cargo"))
    return comps


_DISPATCH = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
    "pom.xml": parse_pom,
    "go.sum": parse_go_sum,
    "go.mod": parse_go_mod,
    "cargo.toml": parse_cargo_toml,
}


def read_manifest(path: str | Path) -> List[Component]:
    """Detect the manifest type from its filename and parse it."""
    path = Path(path)
    fname = path.name.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    parser = _DISPATCH.get(fname)
    if parser is None:
        if fname.endswith("requirements.txt") or "requirements" in fname:
            parser = parse_requirements
        elif fname == "cargo.lock":
            parser = parse_cargo_toml
        else:
            raise ValueError(f"Unsupported manifest file: {path.name}")
    return parser(text)
