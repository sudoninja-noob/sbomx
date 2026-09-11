import json
import xml.etree.ElementTree as ET

from sbomx.core.component import Component
from sbomx.generators.cyclonedx import build_bom_dict, build_bom_xml
from sbomx.inputs.sbom_reader import parse_sbom_text


def _comps():
    c = Component(name="openssl", version="1.1.1t", vendor="openssl",
                  cpe="cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*",
                  purl="pkg:generic/openssl@1.1.1t", license="Apache-2.0")
    c.cves = [{"id": "CVE-2023-0464", "severity": "HIGH", "cvss_score": 7.5,
               "cvss_vector": "CVSS:3.1/AV:N", "description": "x", "source": "nvd",
               "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0464", "published": "2023-03-22"}]
    return [c]


def test_cyclonedx_json_structure():
    bom = build_bom_dict(_comps())
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert len(bom["components"]) == 1
    assert bom["components"][0]["cpe"].startswith("cpe:2.3")
    assert bom["vulnerabilities"][0]["id"] == "CVE-2023-0464"


def test_cyclonedx_json_roundtrip():
    bom = build_bom_dict(_comps())
    comps, meta = parse_sbom_text(json.dumps(bom))
    assert meta["detected_format"] == "cyclonedx-json"
    assert comps[0].name == "openssl"


def test_cyclonedx_xml_wellformed():
    xml = build_bom_xml(_comps())
    root = ET.fromstring(xml)
    assert root.tag.endswith("bom")
