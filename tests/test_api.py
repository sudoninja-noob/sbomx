import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402

from sbomx.api import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["tool"] == "sbomx"


def test_convert(fixtures_dir):
    with open(fixtures_dir / "sample.cyclonedx.json", "rb") as f:
        r = client.post("/api/v1/convert",
                        files={"file": ("sbom.json", f, "application/json")},
                        data={"to": "spdx"})
    assert r.status_code == 200
    assert r.json()["spdxVersion"] == "SPDX-2.3"


def test_scan(fixtures_dir):
    with open(fixtures_dir / "sample_firmware.bin", "rb") as f:
        r = client.post("/api/v1/scan",
                        files={"file": ("fw.bin", f, "application/octet-stream")},
                        data={"format": "cyclonedx"})
    assert r.status_code == 200
    assert len(r.json()["components"]) >= 3


def test_cve_offline(fixtures_dir):
    with open(fixtures_dir / "sample.cyclonedx.json", "rb") as f:
        r = client.post("/api/v1/cve",
                        files={"file": ("sbom.json", f, "application/json")},
                        data={"offline": "true"})
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body and body["tool"] == "sbomx"
