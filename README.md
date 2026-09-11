# sbomx

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)

**SBOM scanner & CVE report tool** for TIC (Testing, Inspection, Certification)
labs — IoT, automotive, and embedded firmware products.

`sbomx` generates Software Bills of Materials in **CycloneDX 1.6** and
**SPDX 2.3** formats, and produces **CVE vulnerability reports** by cross-referencing
**NVD** and **OSV**. It runs as a CLI and a FastAPI REST service.

## Features

- **Flexible inputs (auto-detected)**: firmware/rootfs directories & binaries (ELF/PE),
  existing SBOMs (CycloneDX/SPDX, JSON/XML/tag-value), package manifests
  (`requirements.txt`, `package.json`, `pom.xml`, `go.sum`, `Cargo.toml`, …),
  manual JSON/CSV component lists, and scanner-style tables
  (a `NAME`/`INSTALLED` header, e.g. grype/trivy output).
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

```bash
# Generate an SBOM from a firmware directory
sbomx scan ./firmware/ --format cyclonedx --output sbom.json

# Scan an SBOM / manifest / component list for CVEs → HTML report
sbomx cve --input sbom.json --output cve-report.html

# Choose CVE sources: --source all (default) | nvd | osv
# Use nvd/all for OS packages (busybox), osv for npm/pypi/go deps
sbomx cve --input go.sum --source osv --output cve-report.html

# End-to-end: firmware → SBOM → CVE report
sbomx full ./firmware/ --sbom-format spdx --cve-report html --output-dir ./results/

# Convert between SBOM formats
sbomx convert --input sbom.spdx --to cyclonedx --output sbom.cdx.json

# Start the REST API
sbomx serve --port 8000     # docs at http://localhost:8000/api/v1/docs
```

> If the `sbomx` command isn't on your PATH after install, use the module form:
> `python -m sbomx.cli cve -i sbom.json -o report.html`.

See [docs/usage.md](docs/usage.md) for the full command and API reference,
or the project page at **[index.html](index.html)** (enable GitHub Pages to publish it).

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
