from sbomx.inputs.binary_scanner import scan_directory, _detect_binary_type


def test_detect_elf(fixtures_dir):
    assert _detect_binary_type(fixtures_dir / "sample_firmware.bin") == "ELF"


def test_string_scan_finds_libraries(fixtures_dir):
    comps = scan_directory(fixtures_dir / "sample_firmware.bin")
    found = {(c.name, c.version) for c in comps}
    assert ("openssl", "1.1.1t") in found
    assert ("busybox", "1.36.0") in found
    assert ("zlib", "1.2.13") in found


def test_components_have_identifiers(fixtures_dir):
    comps = scan_directory(fixtures_dir / "sample_firmware.bin")
    openssl = next(c for c in comps if c.name == "openssl")
    assert openssl.cpe.startswith("cpe:2.3:a:openssl")
    assert openssl.purl.startswith("pkg:generic/openssl")
    assert openssl.evidence.startswith("string-match")
    assert openssl.sha256  # hashed


def test_scan_whole_directory(fixtures_dir):
    comps = scan_directory(fixtures_dir)
    assert any(c.name == "openssl" for c in comps)
