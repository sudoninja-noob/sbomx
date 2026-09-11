from sbomx.core.component import Component
from sbomx.generators.spdx import build_spdx_dict, build_spdx_tag
from sbomx.inputs.sbom_reader import parse_sbom_text


def _comps():
    return [Component(name="zlib", version="1.2.13", vendor="zlib",
                      cpe="cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*",
                      purl="pkg:generic/zlib@1.2.13", license="Zlib")]


def test_spdx_json_structure():
    doc = build_spdx_dict(_comps())
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["documentNamespace"].startswith("https://")
    pkg = doc["packages"][0]
    assert pkg["name"] == "zlib"
    assert any(r["referenceType"] == "cpe23Type" for r in pkg["externalRefs"])
    assert any(r["referenceType"] == "purl" for r in pkg["externalRefs"])


def test_spdx_tag_roundtrip():
    tag = build_spdx_tag(_comps())
    assert tag.startswith("SPDXVersion: SPDX-2.3")
    comps, meta = parse_sbom_text(tag)
    assert meta["format"] == "SPDX"
    assert comps[0].name == "zlib"
    assert comps[0].cpe and "zlib" in comps[0].cpe


def test_spdx_json_roundtrip():
    import json
    doc = build_spdx_dict(_comps())
    comps, meta = parse_sbom_text(json.dumps(doc))
    assert comps[0].version == "1.2.13"
