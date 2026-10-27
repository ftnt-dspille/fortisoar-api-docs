"""Answer one question per operation: does it accept a JWT? does it accept an API key?

A status code alone does not answer that: a 400 or 404 can mean "bad request"
just as easily as "bad credential". So every operation in the built spec is
sent four ways through pyfsr:

    valid JWT        pyfsr client built with username/password
    valid API key    a throwaway key with the JWT user's roles and teams (mirror_key.py)
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

    .venv/bin/python src/auth_probe.py                 # writes build/auth_probe/<version>.json
    .venv/bin/python src/auth_probe.py --only /api/3/  # re-probe a path prefix, keep the rest
    .venv/bin/python src/auth_probe.py --env ../.env.fsr801-beta   # another box / version
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pyfsr import ExportTemplate, FortiSOAR

from mirror_key import mint, mirror_api_key, remove

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "build" / "fortisoar.curated.openapi.yaml"
OUT_DIR = ROOT / "build" / "auth_probe"

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

# Routes where the junk body is DESTRUCTIVE and a measured no-op body must be
# sent instead (with valid credentials too). The audit purge treats a missing
# `uptoDate` as "no date filter" and would delete the entire audit log, so the
# probe sends `{"uptoDate": 0}` -- `transactionDate < 0` matches no record
# (live-verified: response 200 {}, record count unchanged).
SAFE_BODIES = {
    ("POST", "/api/gateway/audit/activities/delete"): {"uptoDate": 0},
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
        msg = " ".join(str(body.get(k, "")) for k in ("type", "message", "detail", "error", "title", "failure"))
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


def _deep_logout(client: FortiSOAR) -> tuple[str, str]:
    """Log out a disposable copy of this credential (a fresh login, or a second
    mirror key), so the probe's own stays valid. Yes only when the credential
    is refused afterwards: on 8.0.0 a JWT logout answers 200 with an error page."""
    env = os.environ
    kw = {"verify_ssl": client.verify_ssl, "suppress_insecure_warnings": True, "max_retries": 0}
    jwt = FortiSOAR(env["FSR_BASE_URL"], username=env["FSR_USERNAME"], password=env["FSR_PASSWORD"], **kw)

    def logout_then_reuse(c: FortiSOAR) -> tuple[int, int]:
        header = c.auth.get_auth_headers()  # pinned: a refresh would hide the result
        out = c.request("POST", "/api/3/logout", headers=header, raise_on_status=False)
        after = c.request("GET", "/api/3/actors/current", headers=header, raise_on_status=False)
        return out.status_code, after.status_code

    if client.auth.auth_type.lower().startswith("api"):
        with mirror_api_key(jwt) as key:
            code, after = logout_then_reuse(FortiSOAR(env["FSR_BASE_URL"], api_key=key, **kw))
    else:
        code, after = logout_then_reuse(jwt)
    worked = 200 <= code < 300 and after == 401
    return ("YES" if worked else "NO"), f"real logout of a disposable credential: {code}, then reuse: {after}"


def _jwt_from_env(client: FortiSOAR) -> FortiSOAR:
    env = os.environ
    return FortiSOAR(env["FSR_BASE_URL"], username=env["FSR_USERNAME"], password=env["FSR_PASSWORD"],
                     verify_ssl=client.verify_ssl, suppress_insecure_warnings=True, max_retries=0)


def _verdict_of(call) -> tuple[str, str]:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the rejection is the measurement
        code = getattr(exc, "status_code", None)
        rejected = code in (401, 403) or "credential" in str(exc).lower()
        return ("NO" if rejected else "ERROR"), f"real body: {code} {type(exc).__name__} {str(exc)[:50]}"
    return "YES", "real body: accepted"


def _deep_query_related(client: FortiSOAR) -> tuple[str, str]:
    """The indicators linked to a real alert (a made-up id only 404s)."""
    alerts = _jwt_from_env(client).request("GET", "/api/3/alerts", params={"$limit": 1}).json()["hydra:member"]
    if not alerts:
        return "ERROR", "real body: no alert to read links from"
    path = f"/api/query/alerts/{alerts[0]['uuid']}/indicators"
    verdict, why, _ = _step(client, "POST", path, data={"logic": "AND", "filters": []}, params={"$limit": 1})
    return verdict, why


def _deep_auth_config(client: FortiSOAR) -> tuple[str, str]:
    """Write an auth option back to the value it already has (a no-op change)."""
    current = _jwt_from_env(client).auth_config.get("API-KEYS")["api_key_validity_max"]
    return _verdict_of(lambda: client.auth_config.set("api_key_validity_max", current))


def _deep_auth_users(client: FortiSOAR) -> tuple[str, str]:
    """Reset the validity of a disposable mirror key (minted and revoked here)."""
    jwt = _jwt_from_env(client)
    binding, _ = mint(jwt)
    try:
        user = str(binding["userId"]).rsplit("/", 1)[-1]
        return _verdict_of(lambda: client.api_users.reset_validity(user, 1))
    finally:
        remove(jwt, binding)


def _deep_mcp(server: str, call: tuple[str, dict] | None = None):
    """List the server's tools (and call a harmless one) through pyfsr's MCP
    client. The junk-body probe gets 406: MCP needs its own transport."""

    def check(client: FortiSOAR) -> tuple[str, str]:
        def run():
            tools = client.mcp.list_tools(server)
            if call:
                client.mcp.call_tool(server, *call)
            return tools

        verdict, why = _verdict_of(run)
        return verdict, why.replace("accepted", f"tools listed{' and ' + call[0] + ' called' if call else ''}")

    return check


def _connector_mcp(client: FortiSOAR) -> tuple[str, str]:
    """A connector MCP server registered on this box, if any."""
    jwt = _jwt_from_env(client)
    for cfg in jwt.ai.mcp_configs():
        url = str(getattr(cfg, "url", "") or "")
        if "/mcp/connector/" in url:
            return _deep_mcp("connector:" + url.rstrip("/").rsplit("/", 1)[-1])(client)
    return "UNTESTED", "no connector MCP server registered on this box"


def _step(client: FortiSOAR, method: str, path: str, **kw):
    """One real request: ``(verdict, why, response)``; non-2xx raises nothing."""
    r = client.request(method, path, raise_on_status=False, **kw)
    if 200 <= r.status_code < 300:
        return "YES", f"real body: {r.status_code}", r
    verdict = "NO" if r.status_code in (401, 403) or "credential" in r.text.lower() else "ERROR"
    return verdict, f"real body: {r.status_code} {_signature(r)[1][:50]!r}", r


def _chain(ops: list[str], run):
    """A create -> change -> delete sequence on throwaway records that settles
    several ops at once. Runs once per credential; each op reads its step."""
    cache: dict[int, dict[str, tuple[str, str]]] = {}

    def for_op(op: str):
        def check(client: FortiSOAR) -> tuple[str, str]:
            if id(client) not in cache:
                cache[id(client)] = run(client)
            return cache[id(client)].get(op, ("UNTESTED", "earlier step in the chain failed"))
        return check

    return {op: for_op(op) for op in ops}


def _bulk_alert_chain(client: FortiSOAR) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    name = f"authprobe-{secrets.token_hex(4)}"
    out["POST /api/3/insert/{moduleType}"] = _verdict_of(
        lambda: client.records("alerts").bulk_insert([{"name": name}], resolve_picklists=False))
    jwt = _jwt_from_env(client)
    if out["POST /api/3/insert/{moduleType}"][0] != "YES":
        # Still measure update/delete with this credential, on a record JWT makes.
        jwt.records("alerts").bulk_insert([{"name": name}], resolve_picklists=False)
    found = jwt.request("GET", "/api/3/alerts", params={"name": name}).json().get("hydra:member") or []
    iris = [m["@id"] for m in found]
    try:
        if iris:
            out["PUT /api/3/update/{moduleType}"] = _step(
                client, "PUT", "/api/3/update/alerts", data={"data": [{"@id": iris[0], "name": name + "-u"}]})[:2]
            out["DELETE /api/3/delete/{moduleType}"] = _step(
                client, "DELETE", "/api/3/delete/alerts", data={"ids": [i.rsplit("/", 1)[-1] for i in iris]})[:2]
    finally:
        for iri in iris:
            jwt.request("DELETE", iri, raise_on_status=False)
    return out


def _picklist_name_chain(client: FortiSOAR) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    v, why, r = _step(client, "POST", "/api/3/picklist_names", data={"name": f"authprobe-{secrets.token_hex(4)}"})
    out["POST /api/3/picklist_names"] = (v, why)
    if v == "YES":
        uuid = r.json()["uuid"]
        out["DELETE /api/3/picklist_names/{uuid}"] = _step(client, "DELETE", f"/api/3/picklist_names/{uuid}")[:2]
        _jwt_from_env(client).request("DELETE", f"/api/3/picklist_names/{uuid}", raise_on_status=False)
    return out


_SEVERITY_EXPORT: dict[str, Path] = {}


def _severity_export(jwt: FortiSOAR) -> Path:
    """A one-picklist export bundle (made once per run, by JWT: API-key exports never run)."""
    if "zip" not in _SEVERITY_EXPORT:
        exports = jwt.export_config
        tmpl = exports.create_template(ExportTemplate(f"authprobe-{secrets.token_hex(4)}").add_picklist("Severity"))
        try:
            out = Path(tempfile.mkdtemp(prefix="authprobe-")) / "severity.zip"
            _SEVERITY_EXPORT["zip"] = Path(exports.export_by_template_uuid(tmpl["uuid"], str(out), poll_interval=3))
        finally:
            exports.delete_template(tmpl["uuid"])
    return _SEVERITY_EXPORT["zip"]


def _import_chain(client: FortiSOAR) -> dict[str, tuple[str, str]]:
    """Import the Severity picklist back onto itself. Both import routes start a
    background job, so a 2xx proves nothing: GET counts once the job's options
    are generated, PUT once the job reports Import Complete. When this
    credential cannot generate options, JWT prepares a fresh job so the trigger
    is still measured with this credential."""
    out: dict[str, tuple[str, str]] = {}
    jwt = _jwt_from_env(client)
    bundle = _severity_export(jwt)
    made: list[tuple[str, str]] = []  # (job, file_iri) to delete

    def new_job(c: FortiSOAR) -> str:
        file_iri = c.files.upload(str(bundle))["@id"]
        job = c.import_config.create_job(file_iri)
        made.append((job, file_iri))
        return job

    def options_ready(c: FortiSOAR, job: str) -> bool:
        c.import_config.generate_options(job)
        try:
            c.import_config.wait_for_options(job, timeout=60)
            return True
        except TimeoutError:
            return False

    op = "GET /api/import/{job_uuid}"
    try:
        job = new_job(client)
        if options_ready(client, job):
            out[op] = ("YES", "real body: import options generated")
        else:
            out[op] = ("NO", "real body: import options never generated (60s)")
            job = new_job(jwt)
            if not options_ready(jwt, job):
                return out
        op = "PUT /api/import/{job_uuid}"
        client.import_config.trigger(job)
        status = client.import_config.wait_for_import(job, timeout=120).status
        out[op] = (("YES", "real body: import finished") if status == "Import Complete"
                   else ("NO", f"real body: import never finished (status={status!r})"))
    except Exception as exc:  # noqa: BLE001 -- recorded, not raised
        code = getattr(exc, "status_code", None)
        out.setdefault(op, ("NO" if code in (401, 403) else "ERROR",
                            f"real body: {code} {type(exc).__name__} {str(exc)[:50]}"))
    finally:
        for job, file_iri in made:
            jwt.request("DELETE", f"/api/3/import_jobs/{job}", raise_on_status=False)
            jwt.request("DELETE", file_iri, raise_on_status=False)
    return out


def _api_key_binding_chain(client: FortiSOAR) -> dict[str, tuple[str, str]]:
    """JWT mints a key *user* (an /api/auth route); the credential under test binds,
    reads and renames it. JWT revokes it after."""
    out: dict[str, tuple[str, str]] = {}
    jwt = _jwt_from_env(client)
    user = jwt.api_users.create(api_key_validity=1)["uuid"]
    binding = None
    try:
        v, why, r = _step(client, "POST", "/api/3/api_keys",
                          data={"name": f"authprobe-{secrets.token_hex(4)}", "roles": [], "teams": [], "userId": user})
        out["POST /api/3/api_keys"] = (v, why)
        if v == "YES":
            binding = r.json()["uuid"]
        else:  # still measure read/rename with this credential, on a binding JWT makes
            binding = jwt.api_keys.create(name=f"authprobe-{secrets.token_hex(4)}", user_uuid=user, roles=[],
                                          teams=[])["uuid"]
        if binding:
            out["GET /api/3/api_keys/{uuid}"] = _step(client, "GET", f"/api/3/api_keys/{binding}")[:2]
            out["PUT /api/3/api_keys/{uuid}"] = _step(client, "PUT", f"/api/3/api_keys/{binding}",
                                                      data={"name": f"authprobe-{secrets.token_hex(4)}"})[:2]
    finally:
        if binding:
            jwt.api_keys.delete(binding)
        jwt.api_users.revoke(user)
    return out


def _people_chain(client: FortiSOAR) -> dict[str, tuple[str, str]]:
    """People-record writes with a real body, real record.

    A bare-string probe body is misleading here: das rejects it with a 400
    *before* the RBAC check, so a key that would be refused with a real body
    reads as YES. This chain sends a real create (unique throwaway login),
    and measures GET/PUT/DELETE + the resetpassword step against a REAL
    record -- created by the credential under test when RBAC allows, else by
    JWT so the other steps still get measured. Everything is deleted after.
    """
    out: dict[str, tuple[str, str]] = {}
    jwt = _jwt_from_env(client)
    roles = jwt.users.list_roles()
    role_uuid = next((r["uuid"] for r in roles if r.get("name") == "SOC Analyst"),
                     None) or (roles[0]["uuid"] if roles else None)
    if not role_uuid:
        return {op: ("ERROR", "no role resolvable to create a person with")
                for op in ("POST /api/3/people", "GET /api/3/people/{uuid}",
                           "PUT /api/3/people/{uuid}", "DELETE /api/3/people/{uuid}",
                           "POST /api/3/resetpassword")}
    loginid = f"authprobe{secrets.token_hex(4)}"
    payload = {
        "firstname": "Authprobe", "lastname": "People", "email": f"{loginid}@example.com",
        "csActive": True, "accessType": "Named", "roles": [role_uuid],
        "user": {"loginid": loginid, "password": "Authpr0be!Xy9z",
                 "email": f"{loginid}@example.com", "status": 1},
    }
    person = None
    v, why, r = _step(client, "POST", "/api/3/people", data=payload)
    out["POST /api/3/people"] = (v, why)
    if v == "YES":
        person = r.json()["uuid"]
    else:  # still measure read/update/delete/reset with this credential,
        # against a record the JWT admin creates
        _v, _w, r2 = _step(jwt, "POST", "/api/3/people", data=payload)
        if _v == "YES":
            person = r2.json()["uuid"]
    if not person:
        out["GET /api/3/people/{uuid}"] = ("ERROR", "no person record to probe against")
        out["PUT /api/3/people/{uuid}"] = ("ERROR", "no person record to probe against")
        out["DELETE /api/3/people/{uuid}"] = ("ERROR", "no person record to probe against")
        out["POST /api/3/resetpassword"] = ("ERROR", "no person record to probe against")
        return out
    try:
        out["GET /api/3/people/{uuid}"] = _step(client, "GET", f"/api/3/people/{person}")[:2]
        out["PUT /api/3/people/{uuid}"] = _step(client, "PUT", f"/api/3/people/{person}",
                                                data={"department": "authprobe"})[:2]
        out["POST /api/3/resetpassword"] = _step(
            client, "POST", "/api/3/resetpassword",
            data={"loginId": loginid, "password": "Authpr0be!Xy9z2",
                  "confirmPassword": "Authpr0be!Xy9z2"})[:2]
        v, why, d = _step(client, "DELETE", f"/api/3/people/{person}")
        out["DELETE /api/3/people/{uuid}"] = (v, why)
        if v != "YES":  # this credential could not delete; JWT cleans up
            jwt.request("DELETE", f"/api/3/people/{person}", raise_on_status=False)
            person = None
        else:
            person = None
    finally:
        if person:  # belt and suspenders: never leave the probe user behind
            jwt.request("DELETE", f"/api/3/people/{person}", raise_on_status=False)
    return out


def _ingest_indicator(client: FortiSOAR) -> tuple[str, str]:
    """Ingest one documentation-range IP indicator, then delete it."""
    value = f"192.0.2.{secrets.randbelow(250) + 1}"
    note = f"authprobe-{secrets.token_hex(4)}"
    v, why = _verdict_of(lambda: client.feeds.indicators([{"value": value, "type": "IP Address", "source": note}]))
    jwt = _jwt_from_env(client)
    for m in jwt.request("GET", "/api/3/indicators", params={"value": value}).json().get("hydra:member") or []:
        if note in str(m.get("source", "")) or note in str(m):
            jwt.request("DELETE", m["@id"], raise_on_status=False)
    return v, why


# Ops where getting past auth does not mean it works: the handler re-checks
# the credential, or the work never runs. Each is re-measured with a real request.
DEEP_CHECKS = {
    "POST /api/3/bulkupsert/{moduleType}": _deep_bulkupsert,
    "PUT /api/export": _deep_export,
    "POST /api/3/logout": _deep_logout,
    "PUT /api/auth/config": _deep_auth_config,
    "PUT /api/auth/users": _deep_auth_users,
    "POST /api/query/{collection}/{id}/{field}": _deep_query_related,
    "POST /mcp/modules/": _deep_mcp("modules"),
    "POST /mcp/playbooks/": _deep_mcp("playbooks"),
    "POST /mcp/utility/": _deep_mcp("utility", ("get_current_datetime", {})),
    "POST /mcp/connector/{connector_name}/": _connector_mcp,
    "POST /api/ingest-feeds/indicators": _ingest_indicator,
    **_chain(["POST /api/3/insert/{moduleType}", "PUT /api/3/update/{moduleType}",
              "DELETE /api/3/delete/{moduleType}"], _bulk_alert_chain),
    **_chain(["POST /api/3/picklist_names", "DELETE /api/3/picklist_names/{uuid}"], _picklist_name_chain),
    **_chain(["POST /api/3/api_keys", "GET /api/3/api_keys/{uuid}", "PUT /api/3/api_keys/{uuid}"],
             _api_key_binding_chain),
    **_chain(["POST /api/3/people", "GET /api/3/people/{uuid}", "PUT /api/3/people/{uuid}",
              "DELETE /api/3/people/{uuid}", "POST /api/3/resetpassword"], _people_chain),
    **_chain(["GET /api/import/{job_uuid}", "PUT /api/import/{job_uuid}"], _import_chain),
}


# Where the ids for a route live when it is not the route's own parent.
ID_SOURCES = {
    "/api/import/{job_uuid}": "/api/3/import_jobs",
}


def _real_id_path(client: FortiSOAR, spec_paths: dict, path: str) -> str | None:
    """`/x/{id}` with a real id from `GET /x` (first member), or None.

    A 404 on a made-up id only shows the credential got past auth; a 2xx on a
    real one shows it works. Only single-param paths whose parent lists records.
    """
    m = re.fullmatch(r"(.*)/\{[^}]+\}(/?)", path)
    if not m or "{" in m.group(1):
        return None
    parent = ID_SOURCES.get(path) or m.group(1) + m.group(2)
    if path not in ID_SOURCES and "get" not in spec_paths.get(parent, {}) and "get" not in spec_paths.get(m.group(1), {}):
        return None
    # /api/3 reads an unknown query param as a field filter (400), so size the
    # page its way there; elsewhere try `limit`, then no params at all.
    body = None
    for params in ([{"$limit": 1}] if parent.startswith("/api/3/") else [{"limit": 1}, None]):
        try:
            r = client.request("GET", parent, params=params, raise_on_status=False)
        except Exception:  # noqa: BLE001 -- no real id is fine, the probe verdict stands
            continue
        if r.ok:
            body = r.json()
            break
    rows = body.get("hydra:member") or body.get("results") or body.get("data") if isinstance(body, dict) else body
    row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
    ident = row and (row.get("uuid") or row.get("id") or str(row.get("@id", "")).rstrip("/").rsplit("/", 1)[-1])
    return f"{m.group(1)}/{ident}{m.group(2)}" if ident else None


def _bogus_jwt() -> str:
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': 'authprobe', 'exp': 4102444800})}.{secrets.token_urlsafe(32)}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="Only probe paths starting with this prefix (merged into the existing results).")
    ap.add_argument("--env", default=str(ROOT / ".env"),
                    help="Env file for the box to measure (default .env, the box live_test.py captures from).")
    args = ap.parse_args()

    load_dotenv(args.env, override=True)
    args.live_box = Path(args.env).resolve() == (ROOT / ".env").resolve()
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    user, pw = os.environ.get("FSR_USERNAME", ""), os.environ.get("FSR_PASSWORD", "")
    if not (base and user and pw):
        sys.exit("auth_probe needs FSR_BASE_URL, FSR_USERNAME and FSR_PASSWORD in .env")
    common = dict(verify_ssl=os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true",
                  suppress_insecure_warnings=True, max_retries=0,
                  timeout=int(os.environ.get("FSR_TEST_TIMEOUT", "20")))
    jwt = FortiSOAR(base, username=user, password=pw, **common)
    with mirror_api_key(jwt) as api_key:
        return _probe(args, {"jwt": jwt, "apikey": FortiSOAR(base, api_key=api_key, **common)})


def _probe(args: argparse.Namespace, clients: dict[str, FortiSOAR]) -> int:
    for c in clients.values():
        c.auth._unsupported_operations = set()  # measure the server, not pyfsr's guard
    # Bogus credentials ride on the API-key client: it never refreshes, so the
    # override header is what reaches the server.
    bogus = {
        "jwt": lambda: {"Authorization": f"Bearer {_bogus_jwt()}"},
        "apikey": lambda: {"Authorization": f"API-KEY {secrets.token_hex(32)}"},
    }

    def send(client: FortiSOAR, method: str, path: str, headers: dict | None = None):
        data = None if method == "GET" else SAFE_BODIES.get((method, path), PROBE_BODY)
        try:
            return client.request(method, path, data=data, headers=headers, raise_on_status=False)
        except Exception as exc:  # noqa: BLE001 -- transport errors become a recorded ERROR
            return exc

    spec = yaml.safe_load(SPEC_PATH.read_text())
    version = clients["jwt"].version()
    out_path = OUT_DIR / f"{str(version).split('-')[0]}.json"
    # --only re-probes a slice and keeps everything else from the last run.
    results: dict[str, dict] = (json.loads(out_path.read_text())["ops"]
                                if args.only and out_path.exists() else {})
    # ... minus ops the spec no longer has (a renamed or deleted route).
    in_spec = {f"{m.upper()} {path}" for path, item in spec["paths"].items() for m in METHODS if item.get(m)}
    results = {op: rec for op, rec in results.items() if op in in_spec}
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
            if method == "GET" and any(
                rec[mode]["verdict"] == "YES" and not 200 <= (rec[mode]["status"] or 0) < 300 for mode in clients
            ):
                real = _real_id_path(clients["jwt"], spec["paths"], path)
                if real:
                    rec["probed_real"] = real
                    got = {mode: send(client, method, real) for mode, client in clients.items()}
                    codes = {m: getattr(r, "status_code", None) for m, r in got.items()}
                    for mode, code in codes.items():
                        if code and 200 <= code < 300:
                            rec[mode].update(status=code, why=f"{code} on a real id")
                        elif code in (401, 403) and 200 <= (codes["jwt"] or 0) < 300:
                            rec[mode].update(verdict="NO", status=code, why=f"{code} on a real id that JWT reads")
            if op.get("security") == []:
                # Declared credential-free (login, public license): measure that
                # directly. No credential plus a junk body cannot do anything.
                anon = send(clients["apikey"], method, concrete, {"Authorization": None})
                code = getattr(anon, "status_code", None)
                if code and code not in (401, 403):
                    for mode in clients:
                        rec[mode].update(verdict="PUBLIC", why=f"no credential needed: no Authorization gets {code}")
            deep = DEEP_CHECKS.get(f"{method} {path}")
            if deep:
                for mode, client in clients.items():
                    verdict, why = deep(client)
                    rec[mode].update(verdict=verdict, why=why)
            results[f"{method} {path}"] = rec
            print(f"{rec['jwt']['verdict']:>12} {rec['apikey']['verdict']:>12}  {method} {path}", flush=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"fsr_version": version, "live_box": args.live_box,
                                    "ops": results}, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out_path.relative_to(ROOT)} ({len(results)} ops, FortiSOAR {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
