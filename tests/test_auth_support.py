"""How probe results become the auth pills (Scalar x-badges) on each op."""

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


def _pills(op: dict) -> list[tuple[str, str]]:
    kind = {c: k for k, c in build_curated._BADGE_COLOR.items()}
    return [(b["name"], kind[b["color"]]) for b in op.get("x-badges", [])]


def test_versions_that_agree_get_one_pill_each(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("YES", "YES"), "8.0.1": _rec("YES", "YES")})
    assert _pills(op) == [("API key", "yes"), ("JWT", "yes")]
    assert op["description"] == "Body."  # the pills carry it; no banner line
    assert op["security"] == [{"apiKeyAuth": []}, {"bearerJwt": []}]


def test_jwt_only_is_a_red_api_key_pill(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("NO", "YES"), "8.0.1": _rec("NO", "YES")})
    assert _pills(op) == [("API key", "no"), ("JWT", "yes")]
    assert op["security"] == [{"bearerJwt": []}]


def test_versions_that_differ_name_where_the_answer_starts(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("NO", "YES"), "8.0.1": _rec("YES", "YES")})
    assert _pills(op) == [("API key (8.0.1+)", "yes"), ("JWT", "yes")]
    assert op["security"] == [{"apiKeyAuth": []}, {"bearerJwt": []}]  # newest version decides


def test_route_missing_everywhere_is_not_found(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("INCONCLUSIVE", "INCONCLUSIVE", 404, 404)})
    assert _pills(op) == [("Not found", "missing")]
    assert op["x-auth"] == {"apikey": "missing", "jwt": "missing"}


def test_newer_op_gets_the_version_that_introduced_it(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(**{"x-fsr-version": "8.0.1+"}),
                {"8.0.0": _rec("YES", "YES", 404), "8.0.1": _rec("NO", "YES")})
    assert _pills(op) == [("API key", "no"), ("JWT", "yes"), ("8.0.1+", "version")]
    assert op["security"] == [{"bearerJwt": []}]


def test_untested_op_says_so(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("UNTESTED", "UNTESTED")})
    assert _pills(op) == [("Not tested", "untested")]


def test_public_route_has_no_pills(tmp_path, monkeypatch):
    op = _apply(tmp_path, monkeypatch, _spec(), {"8.0.0": _rec("PUBLIC", "PUBLIC")})
    assert _pills(op) == []
    assert op["description"] == "Body."
    assert op["security"] == []
