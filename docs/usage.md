# sbomx usage guide

## Concepts

Every input is normalized into a list of `Component` objects
(`name`, `version`, `type`, `vendor`, `cpe`, `purl`, `license`, `sha256`,
`evidence`, `cves`). Generators turn components into SBOMs; the CVE engine
enriches them with vulnerabilities; reports render the result.

## CLI reference

Global options (before the subcommand):

| Option | Description |
| --- | --- |
| `--offline` | Use only the SQLite cache; make no network calls. |
| `--cache-db PATH` | Override the cache database path. |

### `sbomx scan TARGET`

Generate an SBOM from a directory, binary, or manifest.

```bash
sbomx scan ./firmware/ --format cyclonedx --output sbom.json
sbomx scan app.elf --format spdx-tag --output sbom.spdx
sbomx scan requirements.txt --format cyclonedx-xml -o sbom.xml --include-self
```

- `--format`: `cyclonedx` | `cyclonedx-xml` | `spdx` | `spdx-tag`
- `--include-self`: also emit a component for each detected binary file itself.

### `sbomx cve --input FILE --output FILE`

CVE lookup for an SBOM, manifest, or component list. The report format is
chosen from the output extension (`.json` or `.html`).

```bash
sbomx cve -i sbom.json -o report.html
sbomx cve -i components.csv --format csv -o report.json
sbomx cve -i sbom.json -o report.json --vex-input suppressions.vex.json
```

- `--format`: override the auto-detected input kind (`csv` | `sbom` | `manifest`).
- `--vex-input`: a VEX JSON file; matching CVEs are annotated and `not_affected`
  ones are excluded from summary counts.

### `sbomx full TARGET`

End-to-end pipeline. Writes `sbom.*`, `cve-report.json`, `cve-report.html`
(when requested) and `vex.json` into the output directory.

```bash
sbomx full ./firmware/ --sbom-format spdx --cve-report html --output-dir ./results/
```

### `sbomx convert --input FILE --to FORMAT --output FILE`

Convert an existing SBOM between formats.

```bash
sbomx convert -i sbom.spdx --to cyclonedx -o sbom.cdx.json
```

### `sbomx validate FILE`

Parse an SBOM and report its format, spec version, and component count.

### `sbomx serve`

Start the FastAPI server (`--host`, `--port`).

## Hardware BOM (HBOM)

sbomx builds a hardware inventory alongside software, in one combined SBOM. Both
paths are auto-detected; force them with `--format hbom` / `--format hwprobe`.

### Design-file BOM (`--format hbom`)

Point sbomx at an EDA BOM export (KiCad/Altium/Eagle/generic CSV or JSON). Column
headers are matched fuzzily; it looks for a part number and manufacturer.

| Recognized columns (any casing/spacing) |
| --- |
| `MPN` / `Manufacturer Part Number` / `Part Number` |
| `Manufacturer` / `Mfr` / `Vendor` |
| `Reference` / `Designator` / `RefDes`, `Value`, `Footprint`/`Package`, `Qty` |

```bash
sbomx cve -i board-bom.csv --format hbom --source nvd -o hbom-report.html
```

Each part becomes a `hardware` component with an `mpn`, a `cpe:2.3:h:` string, and
merged reference designators. In CycloneDX it is emitted as a `device` component;
in SPDX as a package with `primaryPackagePurpose: DEVICE`.

### Firmware-inferred inventory (`--format hwprobe`)

When you only have the firmware/device, sbomx extracts hardware from:

- **Device Tree** — `.dts` (or a `dtc`-decompiled `.dtb`): `model` and `compatible`
  strings name the board, SoC, and peripherals.
- **`lspci` / `lspci -nn`** — PCI devices with `vendor:device` IDs.
- **`lsusb`** — USB devices with `idVendor:idProduct`.
- **`/proc/cpuinfo`** — CPU model and SoC.

```bash
# capture on the device, then scan the dumps on your workstation
lspci -nn > lspci.txt ; lsusb > lsusb.txt
sbomx cve -i lspci.txt --format hwprobe --source nvd -o hw-report.html
```

> Hardware CVE lookups use NVD (`--source nvd`); OSV is a software-ecosystem
> database and is skipped for hardware parts. Versionless hardware CPEs are matched
> with NVD's `virtualMatchString`, so coverage is broad but fuzzier than software —
> "no known CVEs" is a valid, documented certification outcome.

## VEX input format

```json
{
  "statements": [
    {
      "vulnerability": "CVE-2023-0464",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "component": "openssl"
    }
  ]
}
```

`status` ∈ `not_affected | affected | fixed | under_investigation`.
Omit `component` to apply the statement to every component.

## REST API

Base path `/api/v1`. Interactive docs at `/api/v1/docs`.

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| POST | `/scan` | `file` (binary/zip/manifest/SBOM), `format` | SBOM JSON/XML |
| POST | `/cve` | `file`, `offline` | CVE report JSON |
| POST | `/full` | `file`, `sbom_format`, `offline` | `{sbom, cve_report}` |
| POST | `/convert` | `file` (SBOM), `to` | converted SBOM |
| GET | `/health` | — | `{status, tool, version}` |

Examples:

```bash
curl -F "file=@firmware.zip" -F "format=cyclonedx" http://localhost:8000/api/v1/scan
curl -F "file=@sbom.json" http://localhost:8000/api/v1/cve
```

## Configuration

Environment variables (or a `.env` file — see `.env.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `NVD_API_KEY` | — | NVD API key (raises rate limit to 50/30s). |
| `SBOMX_CACHE_DB` | `cache.db` | SQLite cache path. |
| `SBOMX_CACHE_TTL_HOURS` | `24` | Cache entry lifetime. |
| `SBOMX_OFFLINE` | — | `1`/`true` forces offline mode. |

## Docker

```bash
docker compose up --build      # API on http://localhost:8000
```

## Notes on optional dependencies

- **Binary analysis** uses `lief` + `python-magic` when present; otherwise falls
  back to magic-number sniffing and regex version-string scanning (pure Python).
- **SBOM generation** is spec-compliant without any library; if
  `cyclonedx-python-lib` / `spdx-tools` are installed they are used for an
  extra validation pass before writing.
