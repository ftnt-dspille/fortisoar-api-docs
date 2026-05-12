"""Health report for the curated FortiSOAR spec.

Loads `build/fortisoar.curated.openapi.yaml` and `build/live_observations.json`
and surfaces categorized inconsistencies — the kind of drift that
accumulates as new ops get added and old ones get edited piecemeal.

Run:
    python src/spec_health.py                # full report, exits non-zero if any issues
    python src/spec_health.py --quiet        # summary counts only, same exit semantics
    python src/spec_health.py --category=auth  # restrict to one category

Categories surfaced:
  live         — ops with no live observation at all.
  auth         — ops that only succeeded under one auth mode.
  params       — query/path params used in a captured example but not declared
                 in the op's `parameters`.
  request      — POST/PUT/PATCH ops with no `requestBody` example
                 (curated or live).
  response     — 2xx response with no `example` and no `schema $ref`.
  description  — empty / one-line / placeholder descriptions.
  schema_drift — captured response has top-level keys outside the declared
                 response schema (only when `schema` is inline `properties`).
  placeholders — examples that still contain unresolved `<...>` placeholders
                 other than the intentional sanitizer tokens.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "build" / "fortisoar.curated.openapi.yaml"
OBS_PATH = ROOT / "build" / "live_observations.json"

VERBS = ("get", "post", "put", "delete", "patch")
SANITIZER_TOKENS = {"<uuid>", "<api-key>", "<self-agent>", "<jwt-token>", "<binary>"}
PLACEHOLDER_RE = re.compile(r"<[A-Za-z][A-Za-z0-9_\- ]{1,40}>")
PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def _iter_ops(spec: dict):
    for path, methods in spec.get("paths", {}).items():
        for verb, op in methods.items():
            if verb not in VERBS:
                continue
            yield path, verb, op


def _has_example(content_blob: dict | None) -> bool:
    if not isinstance(content_blob, dict):
        return False
    for media_type, media in content_blob.items():
        if isinstance(media, dict) and ("example" in media or "examples" in media):
            return True
    return False


def _has_schema_ref(content_blob: dict | None) -> bool:
    if not isinstance(content_blob, dict):
        return False
    for media_type, media in content_blob.items():
        schema = (media or {}).get("schema") if isinstance(media, dict) else None
        if isinstance(schema, dict) and ("$ref" in schema or schema.get("properties")):
            return True
    return False


def _declared_params(op: dict, path_methods: dict) -> set[str]:
    out: set[str] = set()
    for src in (path_methods.get("parameters") or [], op.get("parameters") or []):
        for p in src:
            if isinstance(p, dict) and "name" in p:
                out.add(p["name"])
    return out


def _captured_params(request_body: Any) -> set[str]:
    # We don't capture query params in observations today, so this remains
    # a heuristic stub — it currently returns nothing. Kept so the report
    # has a place to extend once we start logging the URL's query string.
    return set()


def check_live(spec: dict, obs: dict) -> list[str]:
    issues = []
    for path, verb, op in _iter_ops(spec):
        if "x-verified-live" not in op:
            issues.append(f"{verb.upper()} {path}")
    return issues


def check_auth(spec: dict, obs: dict) -> list[str]:
    issues = []
    for path, verb, op in _iter_ops(spec):
        verified = op.get("x-verified-live")
        if not isinstance(verified, list) or not verified:
            continue
        # Single-auth verified (the other mode either 403'd or was gated upstream).
        if len(verified) == 1:
            mode = verified[0]
            obs_key = f"{verb.upper()} {path}"
            by_auth = (obs.get(obs_key) or {}).get("by_auth", {})
            other_status = []
            for m, rec in by_auth.items():
                if m == mode:
                    continue
                if rec.get("gated_upstream"):
                    other_status.append(f"{m}=gated")
                else:
                    other_status.append(f"{m}={rec.get('response_status')}")
            issues.append(f"{verb.upper()} {path}  (works: {mode}; other: {', '.join(other_status) or '?'})")
    return issues


def check_params(spec: dict, obs: dict) -> list[str]:
    """Path-template params that aren't declared in `parameters`."""
    issues = []
    for path, methods in spec.get("paths", {}).items():
        templated = set(PATH_PARAM_RE.findall(path))
        if not templated:
            continue
        for verb in VERBS:
            op = methods.get(verb)
            if not isinstance(op, dict):
                continue
            declared = _declared_params(op, methods)
            missing = templated - declared
            if missing:
                issues.append(f"{verb.upper()} {path}  (missing path params: {sorted(missing)})")
    return issues


def check_request(spec: dict, obs: dict) -> list[str]:
    issues = []
    for path, verb, op in _iter_ops(spec):
        if verb not in ("post", "put", "patch"):
            continue
        rb = op.get("requestBody")
        if not isinstance(rb, dict):
            issues.append(f"{verb.upper()} {path}  (no requestBody)")
            continue
        content = rb.get("content")
        if not _has_example(content) and not _has_schema_ref(content):
            issues.append(f"{verb.upper()} {path}  (requestBody has no example and no schema)")
    return issues


def check_response(spec: dict, obs: dict) -> list[str]:
    issues = []
    for path, verb, op in _iter_ops(spec):
        responses = op.get("responses") or {}
        twoxx = {k: v for k, v in responses.items() if str(k).startswith("2")}
        if not twoxx:
            issues.append(f"{verb.upper()} {path}  (no 2xx response declared)")
            continue
        for code, resp in twoxx.items():
            content = (resp or {}).get("content") if isinstance(resp, dict) else None
            if content is None:
                # 204 is fine; anything else without content is suspect.
                if str(code) != "204":
                    issues.append(f"{verb.upper()} {path}  ({code} has no content)")
                continue
            if not _has_example(content) and not _has_schema_ref(content):
                issues.append(f"{verb.upper()} {path}  ({code} has neither example nor schema)")
    return issues


def check_description(spec: dict, obs: dict) -> list[str]:
    issues = []
    for path, verb, op in _iter_ops(spec):
        desc = (op.get("description") or "").strip()
        # Strip the auto-appended "**Auth coverage:**" line so it doesn't
        # mask a genuinely thin description.
        stripped = re.sub(r"\n*\*\*Auth coverage:\*\*.*$", "", desc, flags=re.S).strip()
        if not stripped:
            issues.append(f"{verb.upper()} {path}  (no description)")
        elif len(stripped) < 40:
            issues.append(f"{verb.upper()} {path}  (description < 40 chars: {stripped!r})")
    return issues


def check_placeholders(spec: dict, obs: dict) -> list[str]:
    """Surface unresolved `<...>` placeholders in examples (other than the
    intentional sanitizer tokens)."""
    issues = []
    for path, verb, op in _iter_ops(spec):
        for kind, blob in (("req", (op.get("requestBody") or {}).get("content")),
                           ("res", _flat_responses(op))):
            if not isinstance(blob, dict):
                continue
            for media in blob.values():
                ex = (media or {}).get("example") if isinstance(media, dict) else None
                if ex is None:
                    continue
                bad = _find_placeholders(ex)
                if bad:
                    issues.append(f"{verb.upper()} {path} ({kind})  unresolved: {sorted(bad)}")
    return issues


def _flat_responses(op: dict) -> dict:
    """Merge content blobs across response codes for placeholder scanning."""
    out: dict[str, Any] = {}
    for code, resp in (op.get("responses") or {}).items():
        content = (resp or {}).get("content") if isinstance(resp, dict) else None
        if isinstance(content, dict):
            for mt, media in content.items():
                out[f"{code}:{mt}"] = media
    return out


def _find_placeholders(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        for m in PLACEHOLDER_RE.finditer(value):
            tok = m.group(0)
            if tok not in SANITIZER_TOKENS:
                found.add(tok)
    elif isinstance(value, dict):
        for v in value.values():
            found |= _find_placeholders(v)
    elif isinstance(value, list):
        for v in value:
            found |= _find_placeholders(v)
    return found


def check_schema_drift(spec: dict, obs: dict) -> list[str]:
    """Captured response top-level keys outside the declared 2xx schema."""
    issues = []
    for path, verb, op in _iter_ops(spec):
        key = f"{verb.upper()} {path}"
        obs_op = obs.get(key)
        if not obs_op:
            continue
        # Use any 2xx auth's response body as the captured shape.
        sample = None
        for rec in (obs_op.get("by_auth") or {}).values():
            if rec.get("response_status") and 200 <= rec["response_status"] < 300:
                sample = rec.get("response_body")
                break
        if not isinstance(sample, dict):
            continue
        # Find inline declared schema for the matching 2xx.
        for code, resp in (op.get("responses") or {}).items():
            if not str(code).startswith("2"):
                continue
            schema = ((resp or {}).get("content", {}).get("application/json", {}) or {}).get("schema")
            if not isinstance(schema, dict):
                continue
            props = schema.get("properties")
            if not isinstance(props, dict):
                continue
            extra = set(sample) - set(props)
            if extra:
                issues.append(f"{verb.upper()} {path}  (response keys not in schema: {sorted(extra)})")
    return issues


CHECKS = {
    "live":         (check_live,         "Ops not exercised by live_test.py"),
    "auth":         (check_auth,         "Ops verified under only one auth mode"),
    "params":       (check_params,       "Path params used in URL but not declared"),
    "request":      (check_request,      "POST/PUT/PATCH ops missing requestBody example/schema"),
    "response":     (check_response,     "2xx responses missing example/schema"),
    "description":  (check_description,  "Empty or near-empty descriptions"),
    "schema_drift": (check_schema_drift, "Captured response has keys outside declared schema"),
    "placeholders": (check_placeholders, "Examples carrying unresolved `<...>` placeholders"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="Summary counts only.")
    ap.add_argument("--category", action="append", choices=sorted(CHECKS),
                    help="Restrict to one or more categories.")
    ap.add_argument("--max", type=int, default=20,
                    help="Max items to print per category in verbose mode (default 20).")
    args = ap.parse_args()

    if not SPEC_PATH.exists():
        sys.exit(f"missing {SPEC_PATH} — run src/build_curated.py first")
    spec = yaml.safe_load(SPEC_PATH.read_text())
    obs = json.loads(OBS_PATH.read_text()) if OBS_PATH.exists() else {}

    categories = args.category or list(CHECKS)
    totals: dict[str, int] = {}
    any_issues = False
    for cat in categories:
        fn, blurb = CHECKS[cat]
        issues = fn(spec, obs)
        totals[cat] = len(issues)
        if not args.quiet:
            mark = "✗" if issues else "✓"
            print(f"\n[{mark}] {cat} — {blurb}: {len(issues)}")
            for line in issues[:args.max]:
                print(f"    {line}")
            if len(issues) > args.max:
                print(f"    ... and {len(issues) - args.max} more")
        if issues:
            any_issues = True

    op_total = sum(1 for _ in _iter_ops(spec))
    print(f"\nspec: {op_total} ops")
    print("totals: " + ", ".join(f"{c}={totals[c]}" for c in categories))
    return 1 if any_issues else 0


if __name__ == "__main__":
    sys.exit(main())
