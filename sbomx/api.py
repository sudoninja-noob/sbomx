"""FastAPI REST API for sbomx.

Endpoints (under /api/v1):
    POST /scan     upload an SBOM/manifest/component file -> SBOM JSON
    POST /cve      upload an SBOM/component file         -> CVE report JSON
    POST /full     upload a file                         -> SBOM + CVE report
    POST /convert  upload an SBOM + target format        -> converted SBOM
    GET  /health   health check
    GET  /docs     Swagger UI (FastAPI default, mounted at /api/v1/docs)
"""
from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

from . import __version__, TOOL_NAME
from .core import scanner
from .core.config import Settings
from .cve.aggregator import CveAggregator
from .generators.cyclonedx import build_bom_dict, build_bom_xml
from .generators.spdx import build_spdx_dict, build_spdx_tag
from .inputs.sbom_reader import read_sbom
from .reports.json_report import build_report

app = FastAPI(
    title="sbomx API",
    version=__version__,
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)


def _save_upload(upload: UploadFile, tmpdir: str) -> Path:
    dest = Path(tmpdir) / (upload.filename or "upload.bin")
    dest.write_bytes(upload.file.read())
    return dest


def _maybe_unzip(path: Path, tmpdir: str) -> Path:
    """If the upload is a zip, extract it and return the extraction dir."""
    if zipfile.is_zipfile(path):
        extract_dir = Path(tmpdir) / "extracted"
        extract_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(path) as zf:
            zf.extractall(extract_dir)
        return extract_dir
    return path


def _sbom_payload(components, fmt: str):
    fmt = (fmt or "cyclonedx").lower()
    if fmt in ("cyclonedx", "cyclonedx-json"):
        return JSONResponse(build_bom_dict(components))
    if fmt in ("cyclonedx-xml",):
        return PlainTextResponse(build_bom_xml(components), media_type="application/xml")
    if fmt in ("spdx", "spdx-json"):
        return JSONResponse(build_spdx_dict(components))
    if fmt in ("spdx-tag", "tag"):
        return PlainTextResponse(build_spdx_tag(components), media_type="text/plain")
    raise HTTPException(400, f"Unknown format: {fmt}")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "tool": TOOL_NAME, "version": __version__}


@app.post("/api/v1/scan")
async def scan(file: UploadFile = File(...), format: str = Form("cyclonedx")):
    with tempfile.TemporaryDirectory() as tmp:
        path = _maybe_unzip(_save_upload(file, tmp), tmp)
        comps, _ = scanner.load_components(path)
        return _sbom_payload(comps, format)


@app.post("/api/v1/cve")
async def cve(file: UploadFile = File(...), offline: bool = Form(False)):
    settings = Settings.load(offline=offline)
    with tempfile.TemporaryDirectory() as tmp:
        path = _save_upload(file, tmp)
        comps, meta = scanner.load_components(path)
        await CveAggregator(settings).enrich_async(comps)
        return JSONResponse(build_report(comps, meta.get("input_kind", "upload")))


@app.post("/api/v1/full")
async def full(file: UploadFile = File(...), sbom_format: str = Form("cyclonedx"),
               offline: bool = Form(False)):
    settings = Settings.load(offline=offline)
    with tempfile.TemporaryDirectory() as tmp:
        path = _maybe_unzip(_save_upload(file, tmp), tmp)
        comps, meta = scanner.load_components(path)
        sbom = build_bom_dict(comps) if "cyclone" in sbom_format else build_spdx_dict(comps)
        await CveAggregator(settings).enrich_async(comps)
        report = build_report(comps, meta.get("input_kind", "upload"))
        return JSONResponse({"sbom": sbom, "cve_report": report})


@app.post("/api/v1/convert")
async def convert(file: UploadFile = File(...), to: str = Form("cyclonedx")):
    with tempfile.TemporaryDirectory() as tmp:
        path = _save_upload(file, tmp)
        comps, _ = read_sbom(path)
        return _sbom_payload(comps, to)
