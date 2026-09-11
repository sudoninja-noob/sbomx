from sbomx.cve.nvd import NvdClient
from sbomx.cve.osv import OsvClient, _compute_cvss31_base
from sbomx.cve.aggregator import _dedup_and_sort
from sbomx.cve.cache import CveCache
from sbomx.core.component import CVE, severity_from_score


NVD_SAMPLE = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2023-0464",
            "published": "2023-03-22T00:00:00",
            "descriptions": [{"lang": "en", "value": "A security issue."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 7.5, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
            "references": [{"url": "https://example.com/a"}],
        }}
    ]
}

OSV_SAMPLE = {
    "vulns": [
        {"id": "GHSA-xxxx", "aliases": ["CVE-2023-0464"],
         "summary": "Same issue",
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
         "references": [{"url": "https://example.com/b"}], "published": "2023-03-22T00:00:00Z"}
    ]
}


def test_nvd_params_concrete_vs_wildcard():
    # Concrete version → exact cpeName lookup.
    p = NvdClient._nvd_params("cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*")
    assert p == {"cpeName": "cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*"}
    # Wildcard version (hardware / versionless) → virtualMatchString prefix.
    p = NvdClient._nvd_params("cpe:2.3:h:espressif:esp32:*:*:*:*:*:*:*:*")
    assert p == {"virtualMatchString": "cpe:2.3:h:espressif:esp32"}


def test_nvd_parse():
    cves = NvdClient._parse(NVD_SAMPLE)
    assert len(cves) == 1
    assert cves[0].id == "CVE-2023-0464"
    assert cves[0].severity == "HIGH"
    assert cves[0].cvss_score == 7.5
    assert cves[0].source == "nvd"


def test_osv_parse_and_cvss_calc():
    cves = OsvClient._parse(OSV_SAMPLE)
    assert cves[0].id == "CVE-2023-0464"  # resolved from alias
    assert cves[0].cvss_score == 7.5       # computed from vector
    assert cves[0].severity == "HIGH"


def test_cvss31_calculator():
    # Known vector for score 9.8 (critical)
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert _compute_cvss31_base(v) == 9.8


def test_severity_banding():
    assert severity_from_score(9.5) == "CRITICAL"
    assert severity_from_score(7.0) == "HIGH"
    assert severity_from_score(4.0) == "MEDIUM"
    assert severity_from_score(1.0) == "LOW"
    assert severity_from_score(None) == "UNKNOWN"


def test_aggregator_dedup_and_sort():
    nvd = NvdClient._parse(NVD_SAMPLE)
    osv = OsvClient._parse(OSV_SAMPLE)
    merged = _dedup_and_sort(nvd + osv)
    assert len(merged) == 1  # deduped by CVE id
    assert "nvd" in merged[0].source and "osv" in merged[0].source
    # references merged
    assert len(merged[0].references) == 2


def test_cache_roundtrip(tmp_path):
    db = str(tmp_path / "cache.db")
    cache = CveCache(db, ttl_hours=24)
    assert cache.get("nvd", "cpe:x") is None
    cache.put("nvd", "cpe:x", [CVE(id="CVE-1", severity="LOW", cvss_score=2.0)])
    got = cache.get("nvd", "cpe:x")
    assert got and got[0].id == "CVE-1"


def test_cache_expiry(tmp_path):
    db = str(tmp_path / "cache.db")
    cache = CveCache(db, ttl_hours=0)  # immediate expiry
    cache.put("nvd", "q", [CVE(id="CVE-2")])
    assert cache.get("nvd", "q") is None
