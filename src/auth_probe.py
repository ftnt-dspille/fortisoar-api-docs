"""Answer one question per operation: does it accept a JWT? does it accept an API key?

A status code alone does not answer that: a 400 or 404 can mean "bad request"
just as easily as "bad credential". So every operation in the built spec is
sent four ways through pyfsr:

    valid JWT        pyfsr client built with username/password
    valid API key    pyfsr client built with api_key
    bogus JWT        Authorization: Bearer <well-formed garbage>
    bogus API key    Authorization: API-KEY <64 random hex>

and each valid response is compared with the bogus one of the same scheme:

    2xx                               -> YES
    same answer as the bogus cred     -> NO (the server never got past auth)
    401, or 403 "Access Denied"       -> NO (credential known, method refused)
    anything else (400/404/422/...)   -> YES (auth passed, the handler rejected the probe body)

Path params get values that cannot exist and write bodies are a bare JSON
string, so a request that passes auth fails in the handler and changes
nothing. Ops where that is not enough (param-less DELETE, publish, purge,
logout, license upload, ...) are only sent with bogus credentials and come
out UNTESTED; `build_curated.py` fills those from a 2xx live capture if there
is one.

pyfsr's API-key client refuses some endpoints before sending (its
`unsupported_operations` guard). That guard is one of the things being
measured, so the probe clears it on its own client.

    .venv/bin/python src/auth_probe.py                 # writes build/auth_probe.json
    .venv/bin/python src/auth_probe.py --only /api/3/  # re-probe a path prefix, keep the rest
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pyfsr import ExportTemplate, FortiSOAR

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "build" / "fortisoar.curated.openapi.yaml"
OUT_PATH = ROOT / "build" / "auth_probe.json"

METHODS = ("get", "post", "put", "patch", "delete")
PROBE_BODY = "authprobe"  # valid JSON, wrong type for every handler
ZERO_UUID = "00000000-0000-0000-0000-000000000000"

# Never sent with a valid credential: a junk body is not enough to make these
# harmless (they ignore the body, or the call itself is the side effect).
UNSAFE = {
    ("POST", "/api/3/logout"),
    ("POST", "/api/auth/license"),
    ("POST", "/api/public/license"),
    ("PUT", "/api/publish"),
    ("PUT", "/api/publish/revert"),
    ("PUT", "/api/3/changepassword"),
    ("PUT", "/api/auth/users"),
    ("PUT", "/api/auth/config"),
    ("POST", "/api/rule/api/system-notification/purge/"),
    ("POST", "/api/wf/api/scheduled/trigger-now/"),
    ("POST", "/api/3/solutionpacks/install"),
    ("POST", "/api/integration/install-connector/"),
    ("PUT", "/api/integration/install-connector/"),
    ("POST", "/ai/enrich/index/build"),
}

# A real module name keeps the request on the module's handler instead of a
# routing 404 that can answer before auth.
MODULE_PARAMS = {"module", "collection", "moduleType", "recordType", "type"}

_NOISE = re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27}|\d+")
_AUTH_WORDS = re.compile(r"credential|unauthori[sz]ed|authenticat|jwt|hmac|api.?key|access denied", re.I)


def _unsafe(method: str, path: str) -> bool:
    return (method, path) in UNSAFE or (method == "DELETE" and "{" not in path)


def _param_value(name: str, schema: dict) -> str:
    if name in MODULE_PARAMS:
        return "alerts"
    if schema.get("type") == "integer":
        return "999999999"
    if "version" in name.lower():
        return "0.0.0"
    if "uuid" in name.lower() or name.lower().endswith("id"):
        return ZERO_UUID
    return "authprobe-nonexistent"


def _concrete_path(path: str, params: list[dict]) -> str:
    schemas = {p["name"]: p.get("schema") or {} for p in params if p.get("in") == "path"}
    return re.sub(r"\{([^}]+)\}", lambda m: _param_value(m.group(1), schemas.get(m.group(1), {})), path)


def _signature(r) -> tuple[int, str]:
    """Status plus what the body says, ids/numbers stripped, for comparing with the bogus baseline."""
    try:
        body = r.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        msg = " ".join(str(body.get(k, "")) for k in ("type", "message", "detail", "error", "title"))
    else:
        msg = re.sub(r"<[^>]+>", " ", r.text or "")
    return r.status_code, _NOISE.sub("#", " ".join(msg.split()))[:120]


def _verdict(valid, bogus) -> tuple[str, str]:
    """(YES|NO|PUBLIC|INCONCLUSIVE, reason)."""
    sv, sb = _signature(valid), _signature(bogus)
    if 200 <= sv[0] < 300:
        if 200 <= sb[0] < 300:
            return "PUBLIC", f"{sv[0]}, a bogus credential also gets {sb[0]}"
        return "YES", str(sv[0])
    if sv == sb:
        if sb[0] in (401, 403) or _AUTH_WORDS.search(sb[1]):
            return "NO", f"{sv[0]}, same as a bogus credential"
        return "INCONCLUSIVE", f"{sv[0]} for valid and bogus alike (route answers before auth)"
    if sv[0] == 401 or (sv[0] in (403, 500) and _AUTH_WORDS.search(sv[1])):
        return "NO", f"{sv[0]} {sv[1][:60]!r} (bogus gets {sb[0]})"
    return "YES", f"{sv[0]} from the handler (bogus gets {sb[0]})"


def _deep_bulkupsert(client: FortiSOAR) -> tuple[str, str]:
    """Upsert one real alert, then delete it. Passing the gateway is not enough
    here: the handler re-checks the credential and rejects API keys with a 500."""
    name = f"authprobe-{secrets.token_hex(4)}"
    try:
        resp = client.records("alerts").bulk_upsert([{"name": name}], resolve_picklists=False)
    except Exception as exc:  # noqa: BLE001 -- the rejection is the measurement
        return "NO", f"real body: {type(exc).__name__} {str(exc)[:60]}"
    for row in resp.get("hydra:member") or []:
        client.alerts.delete(row["uuid"])
    return "YES", "real body: row upserted (and deleted)"


def _deep_export(client: FortiSOAR) -> tuple[str, str]:
    """Export a one-picklist template, then delete the job, file and template.
    An API key's export job is created and never runs, so a 2xx on the
    trigger proves nothing; only a finished job does."""
    exports = client.export_config
    tmpl = exports.create_template(ExportTemplate(f"authprobe-{secrets.token_hex(4)}").add_picklist("Severity"))
    job = None
    try:
        job = exports._trigger_export(tmpl["uuid"], "authprobe.zip")["jobUuid"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status = exports._get_export_status(job)
            if status.status == "Export Complete":
                return "YES", "real body: export finished"
            time.sleep(3)
        return "NO", f"real body: export job never ran (status={status.status!r}, {status.progressPercent}%)"
    finally:
        if job:
            rec = client.request("GET", f"/api/3/export_jobs/{job}", raise_on_status=False).json()
            client.request("DELETE", f"/api/3/export_jobs/{job}", raise_on_status=False)
            if isinstance(rec.get("file"), dict):
                client.request("DELETE", rec["file"]["@id"], raise_on_status=False)
        exports.delete_template(tmpl["uuid"])


# Ops where getting past auth does not mean it works: the handler re-checks
# the credential, or the work never runs. Each is re-measured with a real request.
DEEP_CHECKS = {
    "POST /api/3/bulkupsert/{moduleType}": _deep_bulkupsert,
    "PUT /api/export": _deep_export,
}


def _bogus_jwt() -> str:
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': 'authprobe', 'exp': 4102444800})}.{secrets.token_urlsafe(32)}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="Only probe paths starting with this prefix (merged into the existing results).")
    args = ap.parse_args()

    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("FSR_API_KEY", "")
    user, pw = os.environ.get("FSR_USERNAME", ""), os.environ.get("FSR_PASSWORD", "")
    if not (base and api_key and user and pw):
        sys.exit("auth_probe needs FSR_BASE_URL, FSR_API_KEY, FSR_USERNAME and FSR_PASSWORD in .env")
    common = dict(verify_ssl=os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true",
                  suppress_insecure_warnings=True, max_retries=0,
                  timeout=int(os.environ.get("FSR_TEST_TIMEOUT", "20")))
    clients = {
        "jwt": FortiSOAR(base, username=user, password=pw, **common),
        "apikey": FortiSOAR(base, api_key=api_key, **common),
    }
    for c in clients.values():
        c.auth._unsupported_operations = set()  # measure the server, not pyfsr's guard
    # Bogus credentials ride on the API-key client: it never refreshes, so the
    # override header is what reaches the server.
    bogus = {
        "jwt": lambda: {"Authorization": f"Bearer {_bogus_jwt()}"},
        "apikey": lambda: {"Authorization": f"API-KEY {secrets.token_hex(32)}"},
    }

    def send(client: FortiSOAR, method: str, path: str, headers: dict | None = None):
        data = PROBE_BODY if method != "GET" else None
        try:
            return client.request(method, path, data=data, headers=headers, raise_on_status=False)
        except Exception as exc:  # noqa: BLE001 -- transport errors become a recorded ERROR
            return exc

    spec = yaml.safe_load(SPEC_PATH.read_text())
    version = clients["jwt"].version()
    # --only re-probes a slice and keeps everything else from the last run.
    results: dict[str, dict] = (json.loads(OUT_PATH.read_text())["ops"]
                                if args.only and OUT_PATH.exists() else {})
    for path, item in spec["paths"].items():
        if args.only and not path.startswith(args.only):
            continue
        for m in METHODS:
            op = item.get(m)
            if not op:
                continue
            method = m.upper()
            concrete = _concrete_path(path, (item.get("parameters") or []) + (op.get("parameters") or []))
            rec: dict = {"probed": concrete}
            for mode, client in clients.items():
                b = send(clients["apikey"], method, concrete, bogus[mode]())
                v = None if _unsafe(method, path) else send(client, method, concrete)
                if v is None:
                    verdict, why = "UNTESTED", "unsafe to send with a valid credential"
                elif isinstance(v, Exception) or isinstance(b, Exception):
                    verdict, why = "ERROR", repr(v if isinstance(v, Exception) else b)[:120]
                else:
                    verdict, why = _verdict(v, b)
                rec[mode] = {"verdict": verdict, "why": why,
                             "status": getattr(v, "status_code", None), "bogus_status": getattr(b, "status_code", None)}
            deep = DEEP_CHECKS.get(f"{method} {path}")
            if deep:
                for mode, client in clients.items():
                    verdict, why = deep(client)
                    rec[mode].update(verdict=verdict, why=why)
            results[f"{method} {path}"] = rec
            print(f"{rec['jwt']['verdict']:>12} {rec['apikey']['verdict']:>12}  {method} {path}", flush=True)

    OUT_PATH.write_text(json.dumps({"fsr_version": version,
                                    "ops": results}, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH.relative_to(ROOT)} ({len(results)} ops, FortiSOAR {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
