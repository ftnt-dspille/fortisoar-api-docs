"""The published spec must stay loadable and current.

`build/fortisoar.curated.openapi.yaml` is checked in because GitHub Pages
renders it directly (via scripts/build-public.sh). A malformed or stale file
ships to the site verbatim -- which is exactly how this file once shipped
with a `properties:` mapping that dropped a `name:` key, breaking YAML parsing
and making Scalar render "Document could not be loaded" on the docs page.

These tests guard the two failure modes:
  1. the committed spec parses as YAML and is a well-formed OpenAPI document;
  2. it is up to date with the generator (src/build_curated.py) -- a stale
     checked-in artifact fails the build even if it happens to parse.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "build" / "fortisoar.curated.openapi.yaml"

SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _load_spec() -> dict:
    with SPEC_PATH.open() as fh:
        spec = yaml.safe_load(fh)
    assert isinstance(spec, dict), "spec must be a mapping, not a scalar/sequence"
    return spec


def test_spec_parses_as_valid_yaml():
    _load_spec()


def test_spec_is_openapi_document():
    spec = _load_spec()
    assert spec.get("openapi", "").startswith("3."), "missing/invalid `openapi` version"
    assert isinstance(spec.get("info", {}).get("title"), str)
    assert isinstance(spec.get("paths", {}), dict), "spec must have `paths`"
    assert spec["paths"], "spec has no paths"


def test_spec_matches_generator():
    """Regenerate in place, then require a clean git diff.

    The generator writes both the spec and derives the observations path from
    the same OUT location, so it must run against the real build/ dir. In CI
    (clean checkout) this fails if the committed artifact is stale -- exactly
    the bug that shipped this page.
    """
    proc = subprocess.run(
        [sys.executable, str(SRC / "build_curated.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"build_curated.py failed:\n{proc.stderr[-2000:]}"
    diff = subprocess.run(
        ["git", "diff", "--exit-code", "--", str(SPEC_PATH)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert diff.returncode == 0, (
        "build/fortisoar.curated.openapi.yaml is out of date with "
        "src/build_curated.py. Regenerate it locally "
        "(`.venv/bin/python src/build_curated.py`) and commit the result.\n"
        + diff.stdout[-3000:]
    )
