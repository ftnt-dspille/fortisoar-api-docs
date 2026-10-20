"""How probe results become the "API key: Yes · JWT: Yes" line on each op."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import build_curated  # noqa: E402


def _rec(apikey: str, jwt: str, status: int = 200, bogus: int = 401) -> dict:
    return {m: {"verdict": v, "status": status, "bogus_status": bogus} for m, v in (("apikey", apikey), ("jwt", jwt))}


def _spec(**op_extra) -> dict:
    return {"paths": {"/x": {"get": {"description": "Body.", **op_extra}}}}


def _apply(tmp_path, monkeypatch, spec, boxes):
    probe_dir = tmp_path / "auth_probe"
    probe_dir.mkdir()
    for version, rec in boxes.items():
        (probe_dir / f"{version}.json").write_text(json.dumps({"fsr_version": version, "ops": {"GET /x": rec}}))
    monkeypatch.setattr(build_curated, "AUTH_PROBE_DIR", probe_dir)
    monkeypatch.setattr(build_curated, "OUT", tmp_path / "spec.yaml")
    build_curated._apply_auth_support(spec)
    return spec["paths"]["/x"]["get"]


def test_versions_that_agree_get_one_answer(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("YES", "YES"), "8.0.1": _rec("YES", "YES")})
    assert op["description"] == "**API key: Yes · JWT: Yes**\n\nBody."
    assert op["security"] == [{"apiKeyAuth": []}, {"bearerJwt": []}]


def test_versions_that_differ_name_each(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("NO", "YES"), "8.0.1": _rec("YES", "YES")})
    assert op["description"].startswith("**API key: No on 8.0.0, Yes on 8.0.1 · JWT: Yes**")
    assert op["security"] == [{"apiKeyAuth": []}, {"bearerJwt": []}]  # newest version decides


def test_route_missing_everywhere_is_not_found(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("INCONCLUSIVE", "INCONCLUSIVE", 404, 404)})
    assert op["description"].startswith("**Not found on FortiSOAR 8.0.0**\n\n")
    assert op["x-auth"] == {"apikey": "missing", "jwt": "missing"}


def test_op_newer_than_the_box_is_not_in_that_version(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(**{"x-fsr-version": "8.0.1+"}),
                {"8.0.0": _rec("YES", "YES", 404), "8.0.1": _rec("NO", "YES")})
    assert op["description"].startswith("**API key: Not in this version on 8.0.0, No on 8.0.1 · JWT: "
                                         "Not in this version on 8.0.0, Yes on 8.0.1**")
    assert op["security"] == [{"bearerJwt": []}]


def test_public_route(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("PUBLIC", "PUBLIC")})
    assert op["description"] == "Body."  # no banner: security [] says it
    assert op["security"] == []
