"""sbomx command-line interface (click + rich)."""
from __future__ import annotations

import sys
from pathlib import Path

import click

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _HAVE_RICH = False

from . import __version__
from .core.config import Settings
from .core import scanner
from .reports.json_report import compute_summary, write_json_report
from .reports.html_report import write_html_report
from .reports.spdx_vex import apply_vex_input, write_vex
from .generators.cyclonedx import write_cyclonedx
from .generators.spdx import write_spdx

console = Console(stderr=True) if _HAVE_RICH else None


def _echo(msg: str, style: str = "") -> None:
    if console:
        console.print(msg, style=style)
    else:  # pragma: no cover
        click.echo(msg, err=True)


def _load_or_exit(target, **kwargs):
    """Load components, exiting cleanly (no traceback) on unreadable input."""
    from .inputs.sbom_reader import SbomParseError

    try:
        return scanner.load_components(target, **kwargs)
    except (SbomParseError, ValueError) as exc:
        _echo(f"Could not read input: {exc}", "bold red")
        _echo(
            "sbomx needs a component inventory, not a scanner's finished report.\n"
            "Supported inputs:\n"
            "  • SBOM (CycloneDX/SPDX)            -> just point -i at it\n"
            "  • manifest (requirements.txt,      -> add --format manifest\n"
            "    package.json, go.sum, ...)\n"
            "  • component list (CSV/JSON:         -> add --format csv (or json)\n"
            "    name,version,vendor,type)\n"
            "  • scanner table with a NAME +      -> detected automatically\n"
            "    INSTALLED/VERSION header\n"
            "  • firmware dir/binary              -> use `sbomx scan` / `sbomx full`",
            "yellow",
        )
        sys.exit(2)


def _write_sbom(components, fmt: str, output: str) -> str:
    """Dispatch to the right generator based on format string."""
    fmt = fmt.lower()
    if fmt in ("cyclonedx", "cyclonedx-json", "cdx", "cdx-json"):
        return write_cyclonedx(components, output, "json")
    if fmt in ("cyclonedx-xml", "cdx-xml"):
        return write_cyclonedx(components, output, "xml")
    if fmt in ("spdx", "spdx-json"):
        return write_spdx(components, output, "json")
    if fmt in ("spdx-tag", "spdx-tag-value", "tag"):
        return write_spdx(components, output, "tag")
    raise click.BadParameter(f"Unknown SBOM format: {fmt}")


def _run_cve(components, settings: Settings, sources: str = "all"):
    """Enrich components with CVEs, showing a progress bar when possible."""
    if console and _HAVE_RICH:
        with Progress(
            SpinnerColumn(), TextColumn("[bold]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as prog:
            task = prog.add_task("CVE lookup", total=len(components))
            scanner.enrich_with_cves(
                components, settings, progress=lambda: prog.advance(task), sources=sources
            )
    else:  # pragma: no cover
        scanner.enrich_with_cves(components, settings, sources=sources)
    return components


def _print_summary(components, source: str) -> None:
    summary = compute_summary(components)
    if console and _HAVE_RICH:
        table = Table(title=f"CVE summary — {source}", title_style="bold green")
        table.add_column("Metric"); table.add_column("Count", justify="right")
        for label, key, style in [
            ("Components", "total_components", ""),
            ("Total CVEs", "total_cves", ""),
            ("Critical", "critical", "bold red"),
            ("High", "high", "red"),
            ("Medium", "medium", "yellow"),
            ("Low", "low", "blue"),
        ]:
            table.add_row(label, str(summary[key]), style=style)
        console.print(table)
    else:  # pragma: no cover
        click.echo(str(summary))


# --- CLI group ---------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="sbomx")
@click.option("--offline", is_flag=True, help="Use only cached CVE data; no network.")
@click.option("--cache-db", default=None, help="Path to SQLite cache DB.")
@click.pass_context
def cli(ctx, offline, cache_db):
    """sbomx — SBOM scanner & CVE report tool."""
    ctx.ensure_object(dict)
    ctx.obj["settings"] = Settings.load(offline=offline, cache_db=cache_db)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", default="cyclonedx",
              help="cyclonedx | cyclonedx-xml | spdx | spdx-tag")
@click.option("--output", "-o", required=True, help="Output SBOM path.")
@click.option("--include-self", is_flag=True, help="Emit a component per binary file.")
def scan(target, fmt, output, include_self):
    """Generate an SBOM from a firmware directory, binary, or manifest."""
    comps, meta = _load_or_exit(target, include_self=include_self)
    _echo(f"Loaded {len(comps)} components ({meta['input_kind']})", "green")
    _write_sbom(comps, fmt, output)
    _echo(f"Wrote SBOM → {output}", "bold green")


@cli.command()
@click.option("--input", "-i", "inp", required=True, type=click.Path(exists=True))
@click.option("--format", "fmt", default=None,
              help="Override input kind: csv | json | sbom | manifest | table | hbom | hwprobe.")
@click.option("--output", "-o", required=True, help="Report output path.")
@click.option("--vex-input", default=None, type=click.Path(exists=True),
              help="VEX JSON to mark CVEs not-affected.")
@click.option("--source", "sources", default="all",
              type=click.Choice(["all", "nvd", "osv"]),
              help="Which CVE databases to query (osv is fast, no key).")
@click.pass_context
def cve(ctx, inp, fmt, output, vex_input, sources):
    """Look up CVEs for an SBOM or component list and write a report.

    Output format is chosen from the --output extension (.json or .html).
    """
    settings = ctx.obj["settings"]
    kind = {"csv": "manual", "json": "manual", "sbom": "sbom",
            "manifest": "manifest", "table": "table",
            "hbom": "hbom", "hardware": "hbom", "hwprobe": "hwprobe"}.get(fmt)
    comps, meta = _load_or_exit(inp, kind=kind)
    _echo(f"Loaded {len(comps)} components", "green")
    _run_cve(comps, settings, sources=sources)
    if vex_input:
        n = apply_vex_input(comps, vex_input)
        _echo(f"Applied {n} VEX annotations", "cyan")
    source = meta.get("input_kind", "unknown")
    if output.lower().endswith(".html"):
        write_html_report(comps, output, source)
    else:
        write_json_report(comps, output, source)
    _print_summary(comps, source)
    _echo(f"Wrote report → {output}", "bold green")


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--sbom-format", default="cyclonedx", help="SBOM output format.")
@click.option("--cve-report", default="html", help="json | html")
@click.option("--output-dir", "-d", default="./results", help="Output directory.")
@click.option("--include-self", is_flag=True)
@click.option("--vex-input", default=None, type=click.Path(exists=True))
@click.pass_context
def full(ctx, target, sbom_format, cve_report, output_dir, include_self, vex_input):
    """End-to-end pipeline: input → SBOM + CVE report."""
    settings = ctx.obj["settings"]
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    comps, meta = _load_or_exit(target, include_self=include_self)
    _echo(f"Loaded {len(comps)} components ({meta['input_kind']})", "green")

    sbom_ext = "xml" if "xml" in sbom_format else ("spdx" if "tag" in sbom_format else "json")
    sbom_path = out / f"sbom.{sbom_ext}"
    _write_sbom(comps, sbom_format, str(sbom_path))
    _echo(f"Wrote SBOM → {sbom_path}", "green")

    _run_cve(comps, settings)
    if vex_input:
        apply_vex_input(comps, vex_input)

    source = meta.get("input_kind", "unknown")
    # Always emit the machine-readable JSON report; add HTML when requested.
    write_json_report(comps, str(out / "cve-report.json"), source)
    if cve_report == "html":
        write_html_report(comps, str(out / "cve-report.html"), source)
    write_vex(comps, str(out / "vex.json"))

    _print_summary(comps, source)
    _echo(f"Results written to {out}/", "bold green")


@cli.command()
@click.option("--input", "-i", "inp", required=True, type=click.Path(exists=True))
@click.option("--to", "target_fmt", required=True,
              help="cyclonedx | cyclonedx-xml | spdx | spdx-tag")
@click.option("--output", "-o", required=True)
def convert(inp, target_fmt, output):
    """Convert an existing SBOM between formats."""
    from .inputs.sbom_reader import read_sbom

    comps, meta = read_sbom(inp)
    _echo(f"Read {len(comps)} components from {meta.get('detected_format')}", "green")
    _write_sbom(comps, target_fmt, output)
    _echo(f"Converted → {output} ({target_fmt})", "bold green")


@cli.command()
@click.argument("sbom_file", type=click.Path(exists=True))
def validate(sbom_file):
    """Validate an SBOM file by parsing it and reporting component counts."""
    from .inputs.sbom_reader import read_sbom, SbomParseError

    try:
        comps, meta = read_sbom(sbom_file)
    except SbomParseError as exc:
        _echo(f"INVALID: {exc}", "bold red")
        sys.exit(1)
    _echo(f"VALID — {meta.get('detected_format')} / {meta.get('spec_version','?')} "
          f"with {len(comps)} components", "bold green")


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def serve(host, port):
    """Start the FastAPI REST API server."""
    import uvicorn

    _echo(f"Starting sbomx API on http://{host}:{port} (docs at /api/v1/docs)", "bold green")
    uvicorn.run("sbomx.api:app", host=host, port=port, reload=False)


def main():  # entry point
    cli(obj={})


if __name__ == "__main__":  # pragma: no cover
    main()
