import json

from sbomx.core.config import Settings
from sbomx.core.component import Component
from sbomx.inputs.manifest_reader import (
    parse_requirements, parse_package_json, parse_go_sum, parse_cargo_toml, parse_pom,
)
from sbomx.inputs.manual_entry import parse_json, parse_csv
from sbomx.core import scanner
from sbomx.reports.json_report import compute_summary, build_report
from sbomx.reports.spdx_vex import apply_vex_input, build_vex_document


def test_requirements():
    comps = parse_requirements("requests==2.31.0\nflask>=2.0\n# comment\n-e .\n")
    names = {c.name: c.version for c in comps}
    assert names["requests"] == "2.31.0"
    assert comps[0].purl.startswith("pkg:pypi/")


def test_package_json():
    text = json.dumps({"dependencies": {"express": "^4.18.0", "@scope/pkg": "~1.2.3"}})
    comps = parse_package_json(text)
    names = {c.name for c in comps}
    assert "express" in names and "pkg" in names


def test_go_sum():
    comps = parse_go_sum("github.com/pkg/errors v0.9.1 h1:abc=\n"
                         "github.com/pkg/errors v0.9.1/go.mod h1:def=\n")
    assert len(comps) == 1
    assert comps[0].name == "errors"


def test_cargo_toml():
    comps = parse_cargo_toml('[dependencies]\nserde = "1.0.188"\ntokio = { version = "1.35.0" }\n')
    names = {c.name: c.version for c in comps}
    assert names["serde"] == "1.0.188"
    assert names["tokio"] == "1.35.0"


def test_pom():
    pom = """<project><dependencies>
      <dependency><groupId>org.apache</groupId><artifactId>commons</artifactId><version>1.0</version></dependency>
    </dependencies></project>"""
    comps = parse_pom(pom)
    assert comps[0].name == "commons" and comps[0].version == "1.0"


def test_manual_json_and_csv():
    j = parse_json('[{"name":"openssl","version":"1.1.1t","vendor":"openssl"}]')
    assert j[0].cpe.startswith("cpe:2.3:a:openssl")
    c = parse_csv("name,version,vendor,type\nbusybox,1.36.0,busybox,application\n")
    assert c[0].name == "busybox" and c[0].type == "application"


def test_summary_and_report():
    comp = Component(name="x", version="1")
    comp.cves = [
        {"id": "CVE-1", "severity": "CRITICAL"},
        {"id": "CVE-2", "severity": "LOW"},
        {"id": "CVE-3", "severity": "HIGH", "vex_status": "not_affected"},
    ]
    summary = compute_summary([comp])
    assert summary["critical"] == 1
    assert summary["low"] == 1
    assert summary["total_cves"] == 2  # not_affected excluded
    report = build_report([comp], "test")
    assert report["tool"] == "sbomx"


def test_vex_apply_and_document(tmp_path):
    comp = Component(name="openssl", version="1.1.1t")
    comp.cves = [{"id": "CVE-2023-0464", "severity": "HIGH"}]
    vex = tmp_path / "v.json"
    vex.write_text(json.dumps({"statements": [
        {"vulnerability": "CVE-2023-0464", "status": "not_affected",
         "justification": "not_in_path", "component": "openssl"}]}))
    n = apply_vex_input([comp], vex)
    assert n == 1
    assert comp.cves[0]["vex_status"] == "not_affected"
    doc = build_vex_document([comp])
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


def test_offline_enrich_no_network(fixtures_dir):
    comps, meta = scanner.load_components(fixtures_dir / "sample.cyclonedx.json")
    settings = Settings.load(offline=True, cache_db=":memory:")
    # Offline: should complete without network and leave empty cve lists.
    scanner.enrich_with_cves(comps, settings)
    assert all(isinstance(c.cves, list) for c in comps)


def test_detect_input_kind(fixtures_dir):
    assert scanner.detect_input_kind(fixtures_dir) == "directory"
    assert scanner.detect_input_kind(fixtures_dir / "sample.cyclonedx.json") == "sbom"
    assert scanner.detect_input_kind(fixtures_dir / "sample.spdx") == "sbom"


def test_parse_scanner_table():
    from sbomx.inputs.manual_entry import parse_table, looks_like_table
    text = (
        "NAME     INSTALLED  TYPE    VULNERABILITY   SEVERITY  EPSS         RISK\n"
        "busybox  1.36.1     binary  CVE-2022-48174  Critical  3.2% (87th)  3.0\n"
        "busybox  1.36.1     binary  CVE-2023-42364  Medium    0.4% (36th)  0.2\n"
        "openssl  3.0.2      library CVE-2022-3602    High     1.0% (50th)  2.0\n"
    )
    assert looks_like_table(text)
    comps = parse_table(text)
    names = {(c.name, c.version): c for c in comps}
    assert len(comps) == 2  # busybox rows collapsed
    assert names[("busybox", "1.36.1")].type == "application"
    assert names[("busybox", "1.36.1")].cpe.count(":") == 12  # valid CPE 2.3
    assert names[("openssl", "3.0.2")].type == "library"


def test_table_kind_detection_and_load(tmp_path):
    f = tmp_path / "scan.txt"
    f.write_text("NAME INSTALLED TYPE\nbusybox 1.36.1 binary\n")
    assert scanner.detect_input_kind(f) == "table"
    comps, meta = scanner.load_components(f)
    assert meta["input_kind"] == "table"
    assert comps[0].name == "busybox"


def test_non_table_text_is_not_table():
    from sbomx.inputs.manual_entry import looks_like_table
    assert not looks_like_table("just some prose\nwith no header\n")
