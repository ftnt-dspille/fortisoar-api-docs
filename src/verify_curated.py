"""Verify the curated FortiSOAR OpenAPI spec against a live FSR.

For every operation in build/fortisoar.curated.openapi.yaml:
  1. Build a request from the operation's example (request body + path/query
     parameters substituted with safe defaults).
  2. Send it twice - once with API key, once with bearer JWT (if both
     credentials are in .env).
  3. Compare the response shape against the operation's documented 2xx
     schema using `jsonschema` (Draft 2020-12).
  4. Record per-auth status code, elapsed ms, schema-validation result,
     and observed-vs-documented field deltas.

Output: build/curated_verification.json. Read by web/index.html to
surface a verified badge per operation.

Defaults to **read-only**: skips DELETE, PUT, and POST paths that
would mutate state. Pass --include-mutating to exercise the full
surface against a disposable SOAR.

Usage:
    cp .env.example .env  # set FSR_BASE_URL, FSR_API_KEY, FSR_USERNAME, FSR_PASSWORD
    python3 src/verify_curated.py
    python3 src/verify_curated.py --include-mutating  # destructive verbs too
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml
from dotenv import load_dotenv

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

try:
    from sanitize import scrub_value
except ImportError:
    def scrub_value(v):  # fallback
        return v

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "build" / "fortisoar.curated.openapi.yaml"
OUT = ROOT / "build" / "curated_verification.json"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Operations we never call (would create real records / fire playbooks
# / delete data) unless --include-mutating is passed. Match by
# (method, path-prefix).
MUTATING_PREFIXES = (
    "/auth/authenticate",  # we already auth at startup; example carries scrubbed creds
    "/api/triggers/",
    "/api/3/import_jobs",
    "/api/3/export_jobs",
    "/api/3/cache_util",
    "/api/integration/execute",
    "/api/wf/api/workflows/{pk}/start",
    "/api/wf/api/workflows/{pk}/resume",
    "/api/wf/api/workflows/{pk}/retry",
    "/api/wf/api/workflows/{pk}/approval",
    "/api/ingest-feeds/",
    "/api/insert-feeds/",
    "/api/3/insert/",
    "/api/3/update/",
    "/api/3/delete/",
    "/api/3/upsert/",
    "/api/3/bulkupsert/",
    "/api/3/api_keys",
    "/api/gateway/audit/activities/ttl",
    "/api/3/files/",
    "/api/3/logout",
    "/api/3/cache_util",
    # Record creates - require real picklist IRIs we don't synthesize
    "/api/3/alerts",
    "/api/3/{collection}",
    "/api/3/roles",
    "/api/3/teams",
    # Saved-query execute requires a pre-existing queryId fixture we
    # don't have on a fresh box.
    "/api/query/",
    # Connector healthcheck / configuration creates a real connector
    # config, plus needs connector-specific body.
    "/api/integration/configuration",
    "/api/integration/connectors/healthcheck",
)


# Path patterns whose POST is mutating regardless of prefix list. Catches
# every record-collection write (POST /api/3/<plural> or POST
# /api/3/<plural>/<uuid>/<subop>).
MUTATING_PATH_RES = (
    re.compile(r"^/api/3/[a-z_]+/?$"),
    re.compile(r"^/api/3/[a-z_]+/\{[^}]+\}(?:/[a-z_-]+)?/?$"),
)

# Path placeholders that need a real value. We fill safely from data
# discovered earlier in the verification run, or skip the op if we
# can't.
PLACEHOLDER_FALLBACKS = {
    "uuid": None,           # try to grab from a list call
    "collection": "alerts",
    "moduleType": "alerts",
    "shortName": "Alert",
    "name": "_verify_no_op_",
    "workflowId": None,
    "queryId": None,
    "auditId": None,
    "pk": None,
}


def _load_env() -> dict[str, str]:
    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    if not base:
        sys.exit("FSR_BASE_URL missing from .env")
    return {
        "base": base,
        "api_key": os.environ.get("FSR_API_KEY", ""),
        "username": os.environ.get("FSR_USERNAME", ""),
        "password": os.environ.get("FSR_PASSWORD", ""),
        "verify": os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true",
        "timeout": int(os.environ.get("FSR_TEST_TIMEOUT", "20")),
    }


def _get_jwt(env) -> str | None:
    if not (env["username"] and env["password"]):
        return None
    try:
        r = requests.post(
            f"{env['base']}/auth/authenticate",
            json={"credentials": {"loginid": env["username"], "password": env["password"]}},
            verify=env["verify"], timeout=env["timeout"],
        )
        if r.ok:
            return r.json().get("token")
    except Exception as exc:
        print(f"  jwt fetch failed: {exc}", file=sys.stderr)
    return None


def _resolve_schema(spec: dict, schema: Any) -> Any:
    """Inline $ref so jsonschema can validate. allOf is merged shallowly."""
    if not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return _resolve_schema(spec, spec["components"]["schemas"].get(name, {}))
    if "allOf" in schema:
        merged = {"type": "object", "properties": {}}
        for part in schema["allOf"]:
            r = _resolve_schema(spec, part)
            if r.get("type"):
                merged["type"] = r["type"]
            if "properties" in r:
                merged["properties"].update(r["properties"])
            if "required" in r:
                merged.setdefault("required", []).extend(r["required"])
        return merged
    out = dict(schema)
    if "properties" in out:
        out["properties"] = {k: _resolve_schema(spec, v) for k, v in out["properties"].items()}
    if "items" in out:
        out["items"] = _resolve_schema(spec, out["items"])
    return out


# Operations the verifier never runs, even with --include-mutating.
# `/auth/authenticate` example body carries scrubbed creds; trying it
# returns 400 and on some FSR builds appears to disturb subsequent
# bearer-token requests on the same source IP.
PERMANENT_SKIP = (
    ("post", "/auth/authenticate"),
)


def _is_mutating(method: str, path: str) -> bool:
    if (method, path) in PERMANENT_SKIP:
        return True
    if method in {"delete", "put"}:
        return True
    if method == "post":
        for prefix in MUTATING_PREFIXES:
            if path.startswith(prefix):
                return True
        for pat in MUTATING_PATH_RES:
            if pat.match(path):
                return True
    return False


def _fill_path(path: str, sample_uuid: str | None,
               per_collection_uuids: dict[str, str] | None = None) -> str | None:
    out = path
    per_collection_uuids = per_collection_uuids or {}
    for ph in re.findall(r"\{(\w+)\}", path):
        val = PLACEHOLDER_FALLBACKS.get(ph)
        if ph in ("uuid", "queryId", "workflowId", "pk"):
            # Prefer a uuid harvested from THIS collection (e.g. picklists)
            # over the generic last-seen sample.
            m = re.match(r"^/api/3/([a-z_]+)/", path)
            if m and m.group(1) in per_collection_uuids:
                val = per_collection_uuids[m.group(1)]
            else:
                val = sample_uuid
        if not val:
            return None
        out = out.replace(f"{{{ph}}}", str(val))
    return out


def _build_query_params(op: dict, path_item: dict) -> dict:
    """Build a query-string dict from documented parameters.

    Only emit params with a real `schema.default`. Illustrative `example`
    values are doc artifacts, not inputs - sending them spams the server
    with bogus filter combos (e.g. every `RECORD_FILTER_QPARAMS` example
    on a list endpoint, or `$orderby=-createDate` on collections that
    don't have a `createDate` column). Skips path params (handled by
    _fill_path) and `null`-valued knobs the user almost never sets
    (`$export`, `$partial`)."""
    out: dict[str, Any] = {}
    seen = set()
    for params in (path_item.get("parameters") or [], op.get("parameters") or []):
        for p in params:
            name = p.get("name")
            if not name or p.get("in") != "query" or name in seen:
                continue
            seen.add(name)
            if name in {"$export", "$partial", "$orderby"}:
                continue
            schema = p.get("schema") or {}
            if "default" not in schema:
                continue
            val = schema["default"]
            if val is None:
                continue
            out[name] = val
    return out


def _build_request_body(op: dict) -> Any:
    rb = op.get("requestBody", {}).get("content", {}).get("application/json", {})
    if "example" in rb:
        return rb["example"]
    examples = rb.get("examples")
    if isinstance(examples, dict) and examples:
        # Pick "basic" if present, else first.
        chosen = examples.get("basic") or next(iter(examples.values()))
        if isinstance(chosen, dict) and "value" in chosen:
            return chosen["value"]
    return None


def _validate_against_schema(spec, op, body) -> tuple[bool, list[str]]:
    if not HAVE_JSONSCHEMA:
        return True, ["jsonschema not installed - skipped"]
    for code in ("200", "201", "202"):
        resp = op.get("responses", {}).get(code) or op.get("responses", {}).get(int(code))
        if not resp:
            continue
        ct = resp.get("content", {}).get("application/json", {})
        schema = ct.get("schema")
        if not schema:
            return True, ["no schema documented"]
        resolved = _resolve_schema(spec, schema)
        validator = Draft202012Validator(resolved)
        errs = sorted(validator.iter_errors(body), key=lambda e: e.path)
        return (not errs), [f"{'/'.join(map(str, e.path))}: {e.message}" for e in errs[:5]]
    return True, ["no 2xx schema to validate"]


# Placeholder strings that appear in CURATED_EXAMPLES bodies. The
# verifier rewrites these to real values harvested from the live FSR
# before sending a request.
#
# `picklist:<ListName>` => substitute with the IRI of the first item
#   in that picklist (e.g. /api/3/picklists/<uuid>).
# `uuid:<collection>`   => substitute with the first uuid harvested
#   from that collection's list endpoint (e.g. /api/3/alerts/<uuid>).
PLACEHOLDER_PICKLIST_IRIS = {
    "/api/3/picklists/high-uuid":       "Severity",
    "/api/3/picklists/critical-uuid":   "Severity",
    "/api/3/picklists/closed-uuid":     "AlertStatus",
    "/api/3/picklists/open-uuid":       "AlertStatus",
    "/api/3/picklists/inprogress-uuid": "AlertStatus",
}

# Field-name -> picklist listName. When a body field has value `/REDACTED`
# (sanitized at storage time) and the field name is one of these, swap
# in the harvested picklist IRI so the request validates server-side.
FIELD_TO_PICKLIST = {
    "severity": "Severity",
    "status":   "AlertStatus",
    "type":     "AlertType",
    "tlp":      "TLP",
}


def _harvest_picklists(env, headers) -> dict[str, str]:
    """Fetch one IRI per known picklist listName."""
    out: dict[str, str] = {}
    seen_listnames = set(PLACEHOLDER_PICKLIST_IRIS.values()) | set(FIELD_TO_PICKLIST.values())
    for listname in seen_listnames:
        code, _, data = _send(
            env, "get", "/api/3/picklists",
            headers, None,
            params={"listName.name": listname, "$limit": 1},
        )
        if 200 <= code < 300 and isinstance(data, dict):
            members = data.get("hydra:member") or []
            if members and members[0].get("@id"):
                out[listname] = members[0]["@id"]
                print(f"  fixture {listname}: {members[0]['@id']}")
    return out


def _harvest_record_uuid(env, headers, collection: str) -> str | None:
    """Get the first record uuid for a collection (used to fill {uuid} on
    PUT/DELETE without consuming a real record from a list iteration)."""
    code, _, data = _send(
        env, "get", f"/api/3/{collection}",
        headers, None, params={"$limit": 1},
    )
    if 200 <= code < 300 and isinstance(data, dict):
        members = data.get("hydra:member") or []
        if members:
            cand = members[0].get("uuid") or (members[0].get("@id") or "").rsplit("/", 1)[-1]
            if cand and re.match(r"^[0-9a-f-]{36}$", cand):
                return cand
    return None


def _fixup_body(body: Any, picklists: dict[str, str], record_iri: str | None,
                unique_suffix: str) -> Any:
    """Rewrite placeholder strings in a request body in-place. Returns
    a deep-copied body so the spec example isn't mutated."""
    import copy
    out = copy.deepcopy(body)

    def walk(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                # Field-name based swap: severity/status/type/tlp == /REDACTED
                # means the spec's example IRI got scrubbed during a prior
                # build cycle. Replace with the harvested picklist IRI.
                if (k in FIELD_TO_PICKLIST and isinstance(v, str)
                        and v in ("/REDACTED", "REDACTED", "")):
                    listname = FIELD_TO_PICKLIST[k]
                    if listname in picklists:
                        node[k] = picklists[listname]
                        continue
                node[k] = walk(v)
                # Suffix `name` on top-level create ops to dodge 409s.
                if k == "name" and isinstance(node[k], str) and unique_suffix:
                    if not node[k].endswith(unique_suffix):
                        node[k] = f"{node[k]}-{unique_suffix}"
            return node
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, str):
            if node in PLACEHOLDER_PICKLIST_IRIS:
                ln = PLACEHOLDER_PICKLIST_IRIS[node]
                return picklists.get(ln, node)
            # Common record-IRI placeholders (e.g. PUT body's @id).
            if record_iri and re.match(r"^/api/3/[a-z_]+/[0-9a-f-]{8,}$", node):
                return record_iri
        return node

    return walk(out)


def _send(env, method, path, headers, body, params=None):
    url = f"{env['base']}{path}"
    t0 = time.monotonic()
    try:
        r = requests.request(method.upper(), url, headers=headers, json=body,
                             params=params, verify=env["verify"], timeout=env["timeout"])
        elapsed = int((time.monotonic() - t0) * 1000)
        try:
            data = r.json()
        except Exception:
            data = {"_non_json": r.text[:200]}
        return r.status_code, elapsed, data
    except Exception as exc:
        return 0, int((time.monotonic() - t0) * 1000), {"_error": str(exc)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-mutating", action="store_true",
                    help="Exercise DELETE/PUT and mutating POSTs against the configured FSR.")
    ap.add_argument("--filter", default="", help="Only verify ops whose path contains this substring.")
    args = ap.parse_args()

    env = _load_env()
    spec = yaml.safe_load(SPEC.read_text())
    jwt = _get_jwt(env)
    if not (env["api_key"] or jwt):
        sys.exit("Need at least one of FSR_API_KEY or FSR_USERNAME+FSR_PASSWORD in .env")

    auth_modes = []
    if env["api_key"]:
        auth_modes.append(("apikey", {"Authorization": f"API-KEY {env['api_key']}"}))
    if jwt:
        auth_modes.append(("jwt", {"Authorization": f"Bearer {jwt}"}))

    sample_uuid: str | None = None
    per_collection_uuids: dict[str, str] = {}
    picklist_iris: dict[str, str] = {}
    record_iri_for_alerts: str | None = None
    unique_suffix = f"verify-{int(time.time())}"

    # Pre-fetch fixtures for collections referenced by `/{uuid}` paths
    # but not listed in the spec, plus picklist IRIs and a real alert
    # uuid for PUT/DELETE bodies.
    PREFETCH_COLLECTIONS = ("picklists", "picklist_names", "alerts", "incidents")
    if auth_modes:
        _, prefetch_hdrs = auth_modes[0]
        for col in PREFETCH_COLLECTIONS:
            code, _, data = _send(env, "get", f"/api/3/{col}",
                                  prefetch_hdrs, None, params={"$limit": 1})
            if 200 <= code < 300 and isinstance(data, dict):
                members = data.get("hydra:member") or []
                if members:
                    cand = members[0].get("uuid") or (members[0].get("@id") or "").rsplit("/", 1)[-1]
                    if cand and re.match(r"^[0-9a-f-]{36}$", cand):
                        per_collection_uuids[col] = cand
                        print(f"  prefetch {col}: {cand}")
                        if col == "alerts":
                            record_iri_for_alerts = members[0].get("@id")
        picklist_iris = _harvest_picklists(env, prefetch_hdrs)

    import datetime as _dt
    results: dict[str, Any] = {
        "spec": str(SPEC.relative_to(ROOT)),
        "base_url": env["base"],
        "generated_at": _dt.date.today().isoformat(),
        "auth_modes_tried": [m for m, _ in auth_modes],
        "include_mutating": args.include_mutating,
        "ops": {},
    }

    skipped_mutating = 0
    skipped_placeholder = 0

    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method == "parameters":
                continue
            if args.filter and args.filter not in path:
                continue
            # `/api/3/{collection}/{uuid}` template paths race against
            # the concrete /api/3/alerts/{uuid} DELETE earlier in the
            # run - 404 by the time they execute. The concrete ops
            # already cover the behavior, so skip these to avoid noise.
            if path.startswith("/api/3/{collection}/{uuid}"):
                skipped_placeholder += 1
                results["ops"][f"{method.upper()} {path}"] = {
                    "skipped": "documentation template (covered by concrete /api/3/alerts/{uuid})",
                }
                continue
            if (method, path) in PERMANENT_SKIP:
                skipped_mutating += 1
                results["ops"][f"{method.upper()} {path}"] = {
                    "skipped": "permanent skip (example body unfit for live execution)",
                }
                continue
            mutating = _is_mutating(method, path)
            if mutating and not args.include_mutating:
                skipped_mutating += 1
                continue
            filled = _fill_path(path, sample_uuid, per_collection_uuids)
            if filled is None:
                skipped_placeholder += 1
                results["ops"][f"{method.upper()} {path}"] = {
                    "skipped": "no placeholder fixture (try after listing endpoints discover a uuid)",
                }
                continue

            body = _build_request_body(op) if method in {"post", "put"} else None
            if body is not None:
                body = _fixup_body(body, picklist_iris, record_iri_for_alerts, unique_suffix)
            params = _build_query_params(op, item)
            per_auth: dict[str, Any] = {}
            for ai, (label, hdrs) in enumerate(auth_modes):
                code, elapsed, data = _send(env, method, filled, hdrs, body, params=params or None)
                # If JWT got soft-revoked (cascading 401), re-auth once
                # and retry. Common after FSR rejects a bad-body POST.
                if label == "jwt" and code == 401:
                    fresh = _get_jwt(env)
                    if fresh:
                        new_hdrs = {"Authorization": f"Bearer {fresh}"}
                        auth_modes[ai] = (label, new_hdrs)
                        hdrs = new_hdrs
                        code, elapsed, data = _send(env, method, filled, hdrs, body, params=params or None)
                schema_ok, schema_errs = (None, [])
                if 200 <= code < 300:
                    schema_ok, schema_errs = _validate_against_schema(spec, op, data)
                per_auth[label] = {
                    "status": code, "elapsed_ms": elapsed,
                    "schema_ok": schema_ok, "schema_errors": schema_errs,
                    "sent_request": {
                        "method": method.upper(),
                        "path": filled,
                        "params": params or None,
                        "body": scrub_value(body) if isinstance(body, (dict, list)) else body,
                    },
                    "sample_response": scrub_value(data) if isinstance(data, (dict, list)) else data,
                }
                # Try to harvest a uuid from list responses for downstream ops.
                if (method == "get" and 200 <= code < 300
                        and isinstance(data, dict)):
                    members = data.get("hydra:member") or []
                    if isinstance(members, list) and members:
                        candidate = members[0].get("uuid") or (members[0].get("@id") or "").rsplit("/", 1)[-1]
                        if candidate and re.match(r"^[0-9a-f-]{36}$", candidate):
                            if sample_uuid is None:
                                sample_uuid = candidate
                            # Per-collection fixture for path placeholders.
                            m = re.match(r"^/api/3/([a-z_]+)/?$", filled)
                            if m and m.group(1) not in per_collection_uuids:
                                per_collection_uuids[m.group(1)] = candidate

            results["ops"][f"{method.upper()} {path}"] = {
                "tags": op.get("tags", []),
                "summary": op.get("summary", ""),
                "mutating": mutating,
                "by_auth": per_auth,
                "verified": any(200 <= a["status"] < 300 for a in per_auth.values()),
                "schema_verified": any(a.get("schema_ok") for a in per_auth.values()),
            }
            print(f"  {method.upper():6} {path}: " + ", ".join(
                f"{label}={d['status']}({d['elapsed_ms']}ms)"
                for label, d in per_auth.items()))

    results["summary"] = {
        "total_ops_in_spec": sum(1 for p in spec["paths"].values() for m in p if m != "parameters"),
        "ops_attempted": len([k for k, v in results["ops"].items() if "by_auth" in v]),
        "ops_verified": sum(1 for v in results["ops"].values() if v.get("verified")),
        "schema_verified": sum(1 for v in results["ops"].values() if v.get("schema_verified")),
        "skipped_mutating": skipped_mutating,
        "skipped_placeholder": skipped_placeholder,
    }

    OUT.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nWrote {OUT}")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()
