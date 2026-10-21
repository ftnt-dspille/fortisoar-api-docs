"""One-off capture: widget publish lifecycle + export/import pipeline round-trip.

Companion to ``misc_reads`` (which owns the export/import template READ
stubs). This script captures the write-side ops that need content this
script owns first:

- ``PUT /api/3/widgets/{uuid}`` publishes a widget; ``DELETE
  /api/3/delete/widgets`` bulk-deletes by ids. Both run on a widget this
  script creates (``live-`` name, ``draft: true`` until published) and
  delete again. Widget names must be alphanumeric on 8.0.0 (dashes 400).
- ``PUT /api/export`` triggers a template-driven export (query params
  ``fileName`` + ``template``); the template is created and deleted here.
- the import pipeline: a minimal solution package (``info.json`` only, no
  content dirs -> nothing installs) is uploaded as a File entity, staged as
  an import job (``POST /api/3/import_jobs``), option generation is kicked
  with ``GET /api/import/{job_uuid}``, and the run is triggered with
  ``PUT /api/import/{job_uuid}``. The package installs nothing, so the
  round-trip mutates nothing beyond our own job/file records, which are
  deleted at the end.

Run: .venv/bin/python scripts/capture_content_pipeline.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import live_test as lt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _minimal_package(label: str) -> bytes:
    """A tgz with ONLY info.json -- a solution package that installs nothing."""
    info = {
        "name": label,
        "version": "1.0.0",
        "fsrMinCompatibility": "7.4.0",
        "type": "solutionpack",
        "local": True,
        "label": label,
        "dependencies": [],
        "publisher": "live-test",
        "certified": "false",
        "description": "live-test empty package for the import pipeline capture",
        "category": [],
        "supportInfo": "live-test",
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = json.dumps(info, indent=2).encode()
        ti = tarfile.TarInfo("info.json")
        ti.size = len(data)
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def main() -> int:
    s = lt.open_session(os.environ.get("FSR_API_KEY", ""))
    s.set_auth("jwt" if "jwt" in s.auth_modes else next(iter(s.auth_modes)))
    stamp = int(time.time())

    print("== widget publish + bulk delete (own widget)")
    wname = f"{lt.LIVE_PREFIX.replace('-', '')}widget{stamp}"  # alphanumeric only
    _, w = s.call("POST", "/api/3/widgets", want=(200, 201, 400, 401, 403, 409, 422),
                  json={"name": wname, "label": "live test widget", "title": "live test widget",
                        "subTitle": "", "draft": True, "installed": False, "enablePublish": False,
                        "isPrivate": False, "version": "1.0.0", "active": True,
                        "viewHtml": "<div>live-test</div>", "editHtml": "",
                        "metadata": {}, "files": []})
    wu = None
    if isinstance(w, dict):
        wu = w.get("uuid") or w.get("@id", "").rsplit("/", 1)[-1]
    if wu:
        s.call("PUT", "/api/3/widgets/{uuid}", want=(200, 204, 400, 401, 403, 404, 422),
               path_params={"uuid": wu},
               json={"name": wname, "version": "1.0.0", "draft": False, "installed": True,
                     "enablePublish": False, "replace": True, "replaceVersions": [],
                     "publishedDate": int(time.time())})
        s.call("DELETE", "/api/3/delete/widgets", want=(200, 204, 400, 401, 403, 404),
               json={"ids": [wu]})
    else:
        print("widget create failed; publish/delete captures skipped")

    print("== export template -> PUT /api/export (template-driven export job)")
    _, t = s.call("POST", "/api/3/export_templates", want=(200, 201, 400, 401, 403),
                  json={"name": f"{lt.LIVE_PREFIX}export-template-{stamp}"})
    tu = (t or {}).get("uuid") if isinstance(t, dict) else None
    if tu:
        try:
            s.call("PUT", "/api/export", want=(200, 400, 401, 403, 422),
                   params={"fileName": f"{lt.LIVE_PREFIX}export-{stamp}", "template": tu},
                   json={})
        finally:
            s.call("DELETE", "/api/3/export_templates/{template_uuid}",
                   want=(200, 204, 401, 403, 404), path_params={"template_uuid": tu})

    print("== import pipeline: minimal package -> file -> job -> options -> run")
    pkg = _minimal_package(f"{lt.LIVE_PREFIX.replace('-', '')}pack{stamp}")
    _, f = s.call("POST", "/api/3/files", want=(200, 201, 400, 401, 403),
                  files={"file": (f"{lt.LIVE_PREFIX}pack-{stamp}.tgz", pkg,
                                  "application/gzip")})
    file_iri = None
    file_uuid = None
    if isinstance(f, dict):
        file_iri = f.get("@id")
        file_uuid = f.get("uuid") or file_iri.rsplit("/", 1)[-1]
    if not file_iri:
        print("file upload failed; import captures skipped")
        lt.save_observations(s)
        return 0

    try:
        _, job = s.call("POST", "/api/3/import_jobs", want=(200, 201, 400, 401, 403, 422),
                        json={"type": "Import Wizard", "file": file_iri})
        ju = (job or {}).get("uuid") if isinstance(job, dict) else None
        if ju:
            s.call("GET", "/api/import/{job_uuid}", want=(200, 400, 404, 401, 403, 500),
                   path_params={"job_uuid": ju})
            s.call("PUT", "/api/import/{job_uuid}", want=(200, 202, 400, 404, 401, 403, 500),
                   path_params={"job_uuid": ju}, json={})
    finally:
        if file_uuid:
            s.call("DELETE", "/api/3/files/{uuid}", want=(200, 204, 401, 403, 404),
                   path_params={"uuid": file_uuid})

    lt.save_observations(s)
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
