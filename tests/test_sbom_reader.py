from sbomx.inputs.sbom_reader import read_sbom, parse_sbom_text, detect_format


def test_parse_cyclonedx_json(fixtures_dir):
    comps, meta = read_sbom(fixtures_dir / "sample.cyclonedx.json")
    assert meta["detected_format"] == "cyclonedx-json"
    assert meta["format"] == "CycloneDX"
    names = {c.name for c in comps}
    assert {"openssl", "busybox"} <= names
    openssl = next(c for c in comps if c.name == "openssl")
    assert openssl.version == "1.1.1t"
    assert openssl.cpe.startswith("cpe:2.3:a:openssl")
    assert openssl.license == "Apache-2.0"
    assert openssl.sha256 == "abc123"


def test_parse_spdx_tag(fixtures_dir):
    comps, meta = read_sbom(fixtures_dir / "sample.spdx")
    assert meta["format"] == "SPDX"
    assert meta["spec_version"] == "SPDX-2.3"
    zlib = next(c for c in comps if c.name == "zlib")
    assert zlib.version == "1.2.13"
    assert zlib.cpe and "zlib" in zlib.cpe
    assert zlib.purl == "pkg:generic/zlib@1.2.13"


def test_detect_format():
    assert detect_format('{"bomFormat":"CycloneDX"}') == "cyclonedx-json"
    assert detect_format('{"spdxVersion":"SPDX-2.3"}') == "spdx-json"
    assert detect_format("SPDXVersion: SPDX-2.3\nPackageName: x") == "spdx-tag"


def test_enrichment_fills_identifiers():
    text = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"foo","version":"1.0"}]}'
    comps, _ = parse_sbom_text(text)
    assert comps[0].cpe is not None
    assert comps[0].purl is not None
