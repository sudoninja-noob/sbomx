from sbomx.utils.cpe import build_cpe
from sbomx.utils.purl import build_purl


def test_cpe_has_13_components():
    # A valid CPE 2.3 formatted string has exactly 13 colon-separated parts:
    # cpe, 2.3, part, vendor, product, version, and 7 more attribute fields.
    cpe = build_cpe("busybox", "1.36.1", "busybox", "application")
    assert cpe.split(":") == [
        "cpe", "2.3", "a", "busybox", "busybox", "1.36.1",
        "*", "*", "*", "*", "*", "*", "*",
    ]
    assert len(cpe.split(":")) == 13


def test_cpe_defaults_vendor_to_name():
    cpe = build_cpe("openssl", "1.1.1t")
    assert cpe == "cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*"


def test_cpe_os_part():
    assert build_cpe("linux_kernel", "6.1", "linux", "os").startswith("cpe:2.3:o:")


def test_purl_generic_and_ecosystem():
    assert build_purl("openssl", "1.1.1t", "generic") == "pkg:generic/openssl@1.1.1t"
    assert build_purl("express", "4.18.0", "npm", namespace="@scope") == \
        "pkg:npm/%40scope/express@4.18.0"
