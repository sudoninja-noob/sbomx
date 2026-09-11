# sbomx

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-56%20passing-brightgreen)
![bom](https://img.shields.io/badge/BOM-software%20%2B%20hardware-purple)

**🌐 Project page: [sudoninja-noob.github.io/sbomx](https://sudoninja-noob.github.io/sbomx/)**

**SBOM scanner & CVE report tool** for TIC (Testing, Inspection, Certification)
labs — IoT, automotive, and embedded firmware products.

`sbomx` generates Software Bills of Materials in **CycloneDX 1.6** and
**SPDX 2.3** formats, and produces **CVE vulnerability reports** by cross-referencing
**NVD** and **OSV**. It runs as a CLI and a FastAPI REST service.

## Features

- **Software + hardware BOM.** Beyond software components, sbomx builds a **Hardware
  BOM (HBOM)** from EDA design-file BOMs (KiCad/Altium/CSV with MPN + manufacturer)
  and infers a hardware inventory from firmware artifacts (Device Tree `.dts`,
  `lspci`/`lsusb`/`cpuinfo` dumps). Hardware parts map to `cpe:2.3:h:` and get real
  NVD hardware CVEs — one combined CycloneDX/SPDX document for a whole product.
- **Flexible inputs (auto-detected)**: firmware/rootfs directories & binaries (ELF/PE),
  existing SBOMs (CycloneDX/SPDX, JSON/XML/tag-value), package manifests
  (`requirements.txt`, `package.json`, `pom.xml`, `go.sum`, `Cargo.toml`, …),
  manual JSON/CSV component lists, scanner-style tables
  (a `NAME`/`INSTALLED` header, e.g. grype/trivy output), hardware BOM CSVs,
  and hardware-probe dumps.
- **SBOM generation**: CycloneDX 1.6 (JSON + XML) and SPDX 2.3 (JSON + tag-value),
  with `purl` + `cpe` identifiers and a vulnerabilities section.
- **CVE engine**: concurrent async NVD + OSV lookups (`--source all|nvd|osv`),
  SQLite cache with 24h TTL, dedup + CVSS v3.1 scoring and severity banding,
  rate-limit backoff.
- **Reports**: JSON, a self-contained dark-theme HTML dashboard (Chart.js pie,
  sortable/filterable table, expandable CVE rows, JSON/CSV export), and VEX documents.
- **No API keys required by default.** NVD works rate-limited; OSV needs no key.
- **Offline mode** (`--offline`) uses only cached data.
- **Graceful degradation**: works without the heavy native deps (`lief`, `libmagic`,
  `cyclonedx-python-lib`, `spdx-tools`) — those are used for extra fidelity/validation
  when installed.

## Install

```bash
git clone https://github.com/sudoninja-noob/sbomx.git
cd sbomx
pip install .            # core (CLI + API + generators + CVE engine)
pip install ".[all]"     # + lief, python-magic, cyclonedx-python-lib, spdx-tools, test deps
```

Requires Python 3.11+.

## Quick start

> If the `sbomx` command isn't on your PATH after install, use the module form:
> `python -m sbomx.cli ...` with the same arguments.

### Software BOM (SBOM)

Software components — firmware directories, binaries, existing SBOMs, and package
manifests. Use `--source all` (or `osv` for language ecosystems like npm/pypi/go).

```bash
# Generate an SBOM from a firmware directory
sbomx scan ./firmware/ --format cyclonedx --output sbom.json

# Scan an SBOM / manifest / component list for CVEs → HTML report
sbomx cve --input sbom.json --source all --output cve-report.html

# Language dependencies (npm/pypi/go) → use OSV
sbomx cve --input go.sum --source osv --output cve-report.html

# End-to-end: firmware → SBOM → CVE report
sbomx full ./firmware/ --sbom-format spdx --cve-report html --output-dir ./results/
```

### Hardware BOM (HBOM)

Hardware components — from an EDA design-file BOM, or inferred from firmware
artifacts. Always use `--source nvd` (hardware CVEs live in NVD; OSV is skipped).

```bash
# From an EDA design-file BOM (CSV with MPN + Manufacturer columns)
sbomx scan board-bom.csv --format cyclonedx --output hardware-sbom.json
sbomx cve --input board-bom.csv --format hbom --source nvd --output hbom-report.html

# Inferred from a device's firmware artifacts (Device Tree / lspci / lsusb)
sbomx cve --input device-tree.dts --format hwprobe --source nvd --output hw-report.html
sbomx cve --input lspci.txt       --format hwprobe --source nvd --output hw-report.html
```

### Convert & serve

```bash
# Convert between SBOM formats
sbomx convert --input sbom.spdx --to cyclonedx --output sbom.cdx.json

# Start the REST API (docs at http://localhost:8000/api/v1/docs)
sbomx serve --port 8000
```

## Input sources

All inputs are auto-detected from content; override with `--format` when needed.

| Input | `--format` | Notes |
| --- | --- | --- |
| Firmware directory / binary (ELF/PE) | *(auto)* | version strings → CPE/purl; ELF/PE sniffed |
| CycloneDX SBOM (JSON/XML) | `sbom` | round-trips components, cpe, purl, hashes |
| SPDX SBOM (JSON / tag-value) | `sbom` | reads `primaryPackagePurpose`, external refs |
| `requirements.txt` / `package.json` / `pom.xml` / `go.sum` / `Cargo.toml` … | `manifest` | pip, npm, maven, go, cargo |
| Component list (CSV/JSON) | `csv` / `json` | `name,version,vendor,type` |
| Scanner table (grype/trivy-style) | `table` | header with `NAME` + `INSTALLED`/`VERSION` |
| **Hardware BOM** (EDA design file) | `hbom` | `MPN` + `Manufacturer` columns → `cpe:2.3:h:` |
| **Hardware probe** (`.dts`, `lspci`, `lsusb`, `cpuinfo`) | `hwprobe` | firmware-inferred device inventory |

## CLI commands

| Command | Purpose |
| --- | --- |
| `sbomx scan TARGET -o FILE` | Build an SBOM from any input (`--format cyclonedx\|cyclonedx-xml\|spdx\|spdx-tag`) |
| `sbomx cve -i FILE -o FILE` | CVE lookup → report (`.json`/`.html`); `--source all\|nvd\|osv`, `--vex-input` |
| `sbomx full TARGET -d DIR` | End-to-end: SBOM + CVE report + VEX into a directory |
| `sbomx convert -i FILE --to FMT -o FILE` | Convert an SBOM between CycloneDX/SPDX |
| `sbomx validate FILE` | Parse and report format, spec version, component count |
| `sbomx serve --port 8000` | Start the FastAPI server (Swagger UI at `/api/v1/docs`) |

Global flags (before the subcommand): `--offline` (cache-only, no network),
`--cache-db PATH`.

## REST API

Run `sbomx serve`; interactive docs at `/api/v1/docs`.

| Method | Path | Returns |
| --- | --- | --- |
| `POST` | `/api/v1/scan` | upload binary/zip/manifest/SBOM → SBOM |
| `POST` | `/api/v1/cve` | upload SBOM/list → CVE report JSON |
| `POST` | `/api/v1/full` | upload → SBOM + CVE report |
| `POST` | `/api/v1/convert` | convert an SBOM between formats |
| `GET` | `/api/v1/health` | health check |

## Output formats

- **SBOM**: CycloneDX 1.6 (JSON + XML), SPDX 2.3 (JSON + tag-value) — with a
  `vulnerabilities` section and VEX annotations when CVEs are present.
- **CVE report**: JSON, and a self-contained dark-theme HTML dashboard (severity
  doughnut, sortable/filterable table, expandable CVE rows, JSON/CSV export).
- **VEX**: a CycloneDX VEX document; suppress non-exploitable CVEs with
  `--vex-input file.vex.json`.

See [docs/usage.md](docs/usage.md) for the full command and API reference,
or the live project page at **[sudoninja-noob.github.io/sbomx](https://sudoninja-noob.github.io/sbomx/)**.

## Compliance alignment

Output aligns with **NTIA minimum elements**, **Executive Order 14028**
(CycloneDX/SPDX, machine-readable), **EN 18031** (version/supplier/license),
and **UN R155 / ISO 21434** (evidence of detection method).

## Development

```bash
pip install ".[dev]"
pytest -q
```

## License &amp; credits

MIT License. Built by [sudoninja-noob](https://github.com/sudoninja-noob) —
[github.com/sudoninja-noob/sbomx](https://github.com/sudoninja-noob/sbomx).
