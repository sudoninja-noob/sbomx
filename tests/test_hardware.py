import json

from sbomx.core import scanner
from sbomx.inputs.hbom_reader import parse_hbom_csv, looks_like_hbom, read_hbom
from sbomx.inputs.hw_probe import (
    parse_device_tree, parse_lspci, parse_lsusb, parse_cpuinfo,
    detect_probe_format, read_hwprobe,
)
from sbomx.generators.cyclonedx import build_bom_dict, _cdx_type
from sbomx.generators.spdx import build_spdx_dict
from sbomx.inputs.sbom_reader import parse_sbom_text


# --- HBOM design-file --------------------------------------------------------

def test_hbom_detect_and_parse(fixtures_dir):
    text = (fixtures_dir / "sample_hbom.csv").read_text()
    assert looks_like_hbom(text)
    comps = read_hbom(fixtures_dir / "sample_hbom.csv")
    by_mpn = {c.mpn: c for c in comps}
    assert "STM32F407VGT6" in by_mpn
    stm = by_mpn["STM32F407VGT6"]
    assert stm.type == "hardware"
    assert stm.is_hardware
    assert stm.vendor == "STMicroelectronics"
    assert stm.cpe.startswith("cpe:2.3:h:")  # hardware CPE part


def test_hbom_merges_reference_designators():
    text = "Reference,Value,MPN,Manufacturer\nR1,10k,RC-10K,Yageo\nR2,10k,RC-10K,Yageo\n"
    comps = parse_hbom_csv(text)
    assert len(comps) == 1  # same MPN merged
    assert "R1" in comps[0].part_ref and "R2" in comps[0].part_ref


def test_software_csv_not_hbom():
    assert not looks_like_hbom("name,version,vendor,type\nopenssl,1.1.1t,openssl,library\n")


# --- Hardware probe ----------------------------------------------------------

def test_device_tree(fixtures_dir):
    text = (fixtures_dir / "sample.dts").read_text()
    assert detect_probe_format(text) == "devicetree"
    comps = parse_device_tree(text)
    names = {c.name for c in comps}
    assert "bcm2711" in names           # SoC from compatible
    assert any("Raspberry Pi 4" in c.name for c in comps)  # board model
    bcm = next(c for c in comps if c.name == "bcm2711")
    assert bcm.vendor == "brcm"
    assert bcm.cpe.startswith("cpe:2.3:h:")


def test_lspci(fixtures_dir):
    comps = parse_lspci((fixtures_dir / "sample_lspci.txt").read_text())
    assert len(comps) == 5
    intel = [c for c in comps if c.vendor == "intel"]
    assert intel and intel[0].mpn and ":" in intel[0].mpn  # pci id like 8086:5914
    assert all(c.is_hardware for c in comps)


def test_lsusb():
    text = ("Bus 001 Device 002: ID 8087:0a2b Intel Corp. Bluetooth\n"
            "Bus 001 Device 003: ID 0bda:8153 Realtek USB Ethernet\n")
    assert detect_probe_format(text) == "lsusb"
    comps = parse_lsusb(text)
    assert len(comps) == 2
    assert comps[0].mpn == "8087:0a2b"


def test_cpuinfo():
    text = ("processor\t: 0\nmodel name\t: ARMv7 Processor rev 3 (v7l)\n"
            "Hardware\t: BCM2835\n")
    assert detect_probe_format(text) == "cpuinfo"
    comps = parse_cpuinfo(text)
    names = {c.name for c in comps}
    assert any("ARMv7" in n for n in names)
    assert "BCM2835" in names


def test_read_hwprobe_dispatch(fixtures_dir):
    comps = read_hwprobe(fixtures_dir / "sample_lspci.txt")
    assert len(comps) == 5


# --- generators + round-trip -------------------------------------------------

def test_cdx_type_mapping():
    assert _cdx_type("hardware") == "device"
    assert _cdx_type("os") == "operating-system"
    assert _cdx_type("library") == "library"


def test_hardware_cyclonedx_and_roundtrip(fixtures_dir):
    comps = read_hbom(fixtures_dir / "sample_hbom.csv")
    bom = build_bom_dict(comps)
    devs = [c for c in bom["components"] if c["type"] == "device"]
    assert devs, "hardware components should map to CycloneDX 'device'"
    assert any(c.get("cpe", "").startswith("cpe:2.3:h:") for c in bom["components"])
    # round-trip: device type + mpn survive
    back, _ = parse_sbom_text(json.dumps(bom))
    assert any(c.is_hardware for c in back)
    assert any(c.mpn for c in back)


def test_hardware_spdx_purpose(fixtures_dir):
    comps = read_hbom(fixtures_dir / "sample_hbom.csv")
    doc = build_spdx_dict(comps)
    assert any(p.get("primaryPackagePurpose") == "DEVICE" for p in doc["packages"])
    # round-trip type
    back, _ = parse_sbom_text(json.dumps(doc))
    assert any(c.is_hardware for c in back)


# --- scanner integration -----------------------------------------------------

def test_scanner_detects_hardware(fixtures_dir):
    assert scanner.detect_input_kind(fixtures_dir / "sample_hbom.csv") == "hbom"
    assert scanner.detect_input_kind(fixtures_dir / "sample.dts") == "hwprobe"
    assert scanner.detect_input_kind(fixtures_dir / "sample_lspci.txt") == "hwprobe"


def test_scanner_loads_hardware(fixtures_dir):
    comps, meta = scanner.load_components(fixtures_dir / "sample_hbom.csv")
    assert meta["input_kind"] == "hbom"
    assert all(c.is_hardware for c in comps)
