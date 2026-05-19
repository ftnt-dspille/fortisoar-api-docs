"""Live, stateful API smoke tests against a real FortiSOAR appliance.

Complements `verify_curated.py` (read-only, per-op) by exercising end-to-end
workflows that involve creating records, calling dependent endpoints with
the real uuids, and then cleaning up.

**Naming contract.** Every record we create has its `name` (or equivalent
identifier) prefixed with `LIVE_PREFIX` ("live-"). On startup we sweep any
records matching that prefix — so a crashed prior run gets cleaned up
automatically on the next start.

Run:
    python src/live_test.py              # sweep, run scenarios, sweep
    python src/live_test.py --sweep-only # just clean up prior leftovers
    python src/live_test.py --scenario api_keys  # run a single scenario
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import time
import urllib.parse
import uuid as _uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
LIVE_PREFIX = "live-"
OBSERVATIONS_PATH = ROOT / "build" / "live_observations.json"

# Regex sanitizers run over JSON string values before persisting observations.
# Keep narrow + ordered so api-key tokens are caught before generic 32-hex.
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_API_KEY_RE = re.compile(r"\b[0-9a-f]{64}\b", re.I)
_AGENT_HASH_RE = re.compile(r"\b[0-9a-f]{32}\b", re.I)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")

# Built at first scrub call from FSR_BASE_URL so we never persist the
# operator's appliance hostname (incl. :port) in observations. Hydra
# `@context` / `@id` / `@vocab` strings carry the absolute base URL.
_BASE_HOST_RE: re.Pattern[str] | None = None
_HOST_PLACEHOLDER = "https://your-soar.example.com"


def _base_host_re() -> re.Pattern[str] | None:
    global _BASE_HOST_RE
    if _BASE_HOST_RE is not None:
        return _BASE_HOST_RE
    base = os.environ.get("FSR_BASE_URL", "").strip().rstrip("/")
    if not base:
        return None
    # Match the full scheme://host[:port] origin so we replace it wholesale,
    # leaving the path intact.
    parsed = urllib.parse.urlsplit(base)
    if not parsed.scheme or not parsed.netloc:
        return None
    _BASE_HOST_RE = re.compile(
        rf"{re.escape(parsed.scheme)}://{re.escape(parsed.netloc)}",
        re.IGNORECASE,
    )
    return _BASE_HOST_RE


def _scrub(value: Any) -> Any:
    """Replace per-instance identifiers with stable placeholders for docs."""
    if isinstance(value, str):
        v = value
        host_re = _base_host_re()
        if host_re is not None:
            v = host_re.sub(_HOST_PLACEHOLDER, v)
        v = _JWT_RE.sub("<jwt-token>", v)
        v = _API_KEY_RE.sub("<api-key>", v)
        v = _UUID_RE.sub("<uuid>", v)
        v = _AGENT_HASH_RE.sub("<self-agent>", v)
        return v
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value

SCENARIOS: dict[str, Callable[["Session"], None]] = {}


def scenario(name: str):
    def deco(fn):
        SCENARIOS[name] = fn
        return fn
    return deco


# --- Session / auth -------------------------------------------------------

@dataclass
class Session:
    base: str
    verify: bool
    timeout: int
    headers: dict[str, str]
    run_id: str
    host: str = ""
    tenant: str = "exo-ui"
    # Map of auth_mode -> full Authorization header value. Populated at
    # session open; `headers` always reflects the currently selected mode.
    auth_modes: dict[str, str] = field(default_factory=dict)
    current_auth: str = ""
    created: list[tuple[str, str]] = field(default_factory=list)  # (kind, identifier)
    # Captured request/response pairs nested by op key + auth mode:
    #   {"METHOD path_template": {"by_auth": {"jwt": {...}, "apikey": {...}}}}
    # The build step uses these to populate the spec's examples per auth mode.
    observations: dict[str, dict] = field(default_factory=dict)

    def set_auth(self, mode: str) -> None:
        if mode not in self.auth_modes:
            raise KeyError(f"unknown auth mode {mode!r}; have {list(self.auth_modes)}")
        self.headers["Authorization"] = self.auth_modes[mode]
        self.current_auth = mode

    def request(self, method: str, path: str, **kw) -> requests.Response:
        url = f"{self.base}{path}"
        r = requests.request(method, url, headers=self.headers, verify=self.verify,
                             timeout=self.timeout, **kw)
        return r

    def call(
        self,
        method: str,
        template: str,
        want: int | tuple[int, ...] | None = None,
        path_params: dict[str, str] | None = None,
        files: dict | None = None,
        **kw,
    ) -> tuple[requests.Response, dict | list | None]:
        """Make a request against a path *template* and record the observation.

        `template` is the OpenAPI path (e.g. `/api/integration/configuration/{config_id}/`).
        `path_params` are substituted into it to form the concrete URL. The pair
        `(method, template)` becomes the key under which the request/response are
        stored for `build_curated.py` to consume.

        When `files` is given, the request is sent as `multipart/form-data` —
        `Content-Type` is omitted from headers so requests picks the right
        boundary. The captured "request body" then summarizes the multipart
        parts rather than echoing the raw binary.
        """
        path = template.format(**(path_params or {}))
        if files is not None:
            # Strip Content-Type so requests sets multipart/form-data with the
            # right boundary. Don't mutate self.headers — copy.
            hdrs = {k: v for k, v in self.headers.items() if k.lower() != "content-type"}
            timeout = kw.pop("timeout", self.timeout)
            r = requests.request(method, f"{self.base}{path}",
                                 headers=hdrs, verify=self.verify, timeout=timeout,
                                 files=files, **kw)
            captured_req: Any = {f: "<binary>" for f in files}
        else:
            r = self.request(method, path, **kw)
            captured_req = _scrub(kw.get("json"))
        try:
            resp_body = r.json() if r.content else None
        except ValueError:
            resp_body = None
        # Record BEFORE assertion so failure cases (e.g. apikey 403 on an
        # admin endpoint) still surface in the per-auth coverage report.
        key = f"{method.upper()} {template}"
        per_op = self.observations.setdefault(key, {"by_auth": {}})
        per_op["by_auth"][self.current_auth] = {
            "request_body": captured_req,
            "response_status": r.status_code,
            "response_body": _scrub(resp_body) if r.status_code < 400 else None,
            "captured_at": _dt.date.today().isoformat(),
        }
        if want is not None:
            want_t = (want,) if isinstance(want, int) else want
            if r.status_code not in want_t:
                raise AssertionError(
                    f"{method} {path} -> {r.status_code} (wanted {want_t}); body={r.text[:300]}"
                )
        return r, resp_body

    def expect(self, method: str, path: str, want: int | tuple[int, ...] = 200, **kw) -> dict | list | None:
        r = self.request(method, path, **kw)
        want_t = (want,) if isinstance(want, int) else want
        if r.status_code not in want_t:
            raise AssertionError(f"{method} {path} -> {r.status_code} (wanted {want_t}); body={r.text[:300]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def track(self, kind: str, identifier: str) -> None:
        self.created.append((kind, identifier))

    def live_name(self, slug: str) -> str:
        return f"{LIVE_PREFIX}{self.run_id}-{slug}"


def open_session() -> Session:
    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    if not base:
        sys.exit("FSR_BASE_URL missing from .env")
    verify = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
    timeout = int(os.environ.get("FSR_TEST_TIMEOUT", "20"))

    api_key = os.environ.get("FSR_API_KEY", "")
    user = os.environ.get("FSR_USERNAME", "")
    pw = os.environ.get("FSR_PASSWORD", "")

    # Try to acquire BOTH auth modes — every scenario then runs once per mode
    # so the docs can surface "JWT only" / "API-KEY only" / "both" per op.
    modes: dict[str, str] = {}
    if user and pw:
        r = requests.post(f"{base}/auth/authenticate",
                          json={"credentials": {"loginid": user, "password": pw}},
                          verify=verify, timeout=timeout)
        if r.ok and r.json().get("token"):
            modes["jwt"] = f"Bearer {r.json()['token']}"
    if api_key:
        modes["apikey"] = f"API-KEY {api_key}"
    if not modes:
        sys.exit("No working auth: set FSR_USERNAME+FSR_PASSWORD and/or FSR_API_KEY in .env")

    first_mode = "jwt" if "jwt" in modes else next(iter(modes))
    host = urllib.parse.urlparse(base).hostname or ""
    tenant = os.environ.get("FSR_TENANT", "exo-ui")
    return Session(
        base=base, verify=verify, timeout=timeout,
        headers={"Authorization": modes[first_mode], "Accept": "application/json",
                 "Content-Type": "application/json"},
        run_id=_uuid.uuid4().hex[:8],
        host=host, tenant=tenant,
        auth_modes=modes, current_auth=first_mode,
    )


# --- Sweep ---------------------------------------------------------------

def sweep(s: Session) -> int:
    """Delete every `live-`-prefixed record across the entity types we touch.

    Add a branch here when a new scenario starts creating a new entity type.
    """
    removed = 0
    removed += _sweep_api_key_scopes(s)
    removed += _sweep_api_key_users(s)
    removed += _sweep_connector_configs(s)
    removed += _sweep_hello_world_connectors(s)
    removed += _sweep_query_objects(s)
    removed += _sweep_alerts(s)
    removed += _sweep_named(s, "/api/3/incidents", "incident")
    removed += _sweep_named(s, "/api/3/tasks", "task")
    removed += _sweep_live_comments(s)
    removed += _sweep_named(s, "/api/3/roles", "role")
    removed += _sweep_named(s, "/api/3/teams", "team")
    return removed


def _sweep_live_comments(s: Session) -> int:
    """DELETE comments whose content carries the LIVE_PREFIX marker."""
    removed = 0
    r = s.request("GET", "/api/3/comments?$limit=200&$search=" + LIVE_PREFIX)
    if not r.ok:
        return 0
    try:
        members = r.json().get("hydra:member", [])
    except ValueError:
        return 0
    for m in members:
        content = m.get("content") or ""
        if LIVE_PREFIX not in content:
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if not uuid_:
            continue
        if s.request("DELETE", f"/api/3/comments/{uuid_}").ok:
            removed += 1
            print(f"  swept comment ({uuid_})")
    return removed


def _sweep_named(s: Session, collection_url: str, kind: str) -> int:
    """Generic sweeper for collections that have a `name` and a uuid-based DELETE."""
    removed = 0
    r = s.request("GET", f"{collection_url}?$limit=200")
    if not r.ok:
        return 0
    try:
        members = r.json().get("hydra:member", [])
    except ValueError:
        return 0
    for m in members:
        name = m.get("name") or ""
        if not name.startswith(LIVE_PREFIX):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if not uuid_:
            continue
        if s.request("DELETE", f"{collection_url}/{uuid_}").ok:
            removed += 1
            print(f"  swept {kind} {name} ({uuid_})")
    return removed


def _sweep_alerts(s: Session) -> int:
    """DELETE /api/3/alerts/{uuid} for any alert whose name starts with LIVE_PREFIX."""
    removed = 0
    r = s.request("GET", "/api/3/alerts?$limit=200&$search=live-")
    if not r.ok:
        return 0
    try:
        members = r.json().get("hydra:member", [])
    except ValueError:
        return 0
    for m in members:
        if not (m.get("name") or "").startswith(LIVE_PREFIX):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if not uuid_:
            continue
        if s.request("DELETE", f"/api/3/alerts/{uuid_}").ok:
            removed += 1
            print(f"  swept alert {m['name']} ({uuid_})")
    return removed


def _sweep_query_objects(s: Session) -> int:
    """DELETE /api/3/user_queries/{uuid} for any saved query with a live-* name."""
    removed = 0
    r = s.request("GET", "/api/3/user_queries?$limit=200")
    if not r.ok:
        return 0
    try:
        members = r.json().get("hydra:member", [])
    except ValueError:
        return 0
    for m in members:
        if not (m.get("name") or "").startswith(LIVE_PREFIX):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if not uuid_:
            continue
        rr = s.request("DELETE", f"/api/3/user_queries/{uuid_}")
        if rr.ok:
            removed += 1
            print(f"  swept saved query {m['name']} ({uuid_})")
    return removed


def _sweep_api_key_scopes(s: Session) -> int:
    """DELETE /api/3/api_keys/{uuid} for any scope whose name starts with LIVE_PREFIX."""
    removed = 0
    data = s.expect("GET", "/api/3/api_keys") or {}
    members = data.get("hydra:member", data if isinstance(data, list) else [])
    for m in members:
        name = m.get("name", "")
        if not name.startswith(LIVE_PREFIX):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if not uuid_:
            continue
        r = s.request("DELETE", f"/api/3/api_keys/{uuid_}")
        if r.status_code < 400:
            removed += 1
            print(f"  swept scope {name} ({uuid_})")
    return removed


def _sweep_hello_world_connectors(s: Session) -> int:
    """Delete any leftover hello-world connector records.

    The connector_lifecycle scenario installs `hello-world` each run; a
    crashed prior run can leave the connector behind. Sweep them every run
    so the captured install response always reflects a virgin install.
    """
    removed = 0
    r = s.request("GET", "/api/integration/connectors/?name=hello-world")
    if not r.ok:
        return 0
    try:
        members = r.json().get("data", [])
    except ValueError:
        return 0
    for m in members:
        cid = m.get("id")
        if not cid:
            continue
        rr = s.request("DELETE", f"/api/integration/connectors/{cid}/")
        if rr.ok:
            removed += 1
            print(f"  swept connector hello-world id={cid}")
    return removed


def _sweep_connector_configs(s: Session) -> int:
    """DELETE any connector configurations whose name starts with LIVE_PREFIX."""
    removed = 0
    r = s.request("GET", "/api/integration/configuration/")
    if not r.ok:
        return 0
    try:
        members = r.json().get("hydra:member", [])
    except ValueError:
        return 0
    for m in members:
        if not (m.get("name") or "").startswith(LIVE_PREFIX):
            continue
        cid = (m.get("@id") or "").rsplit("/", 1)[-1] or m.get("uuid")
        if not cid:
            continue
        rr = s.request("DELETE", f"/api/integration/configuration/{cid}")
        if rr.ok:
            removed += 1
            print(f"  swept config {m['name']} ({cid})")
    return removed


def _sweep_api_key_users(s: Session) -> int:
    """REVOKE any API-key user we created. The doc doesn't expose a hard-delete
    for API-key users, so REVOKE is the terminal state."""
    # We don't have a list-by-prefix on /api/auth/users; rely on session.created
    # for in-run cleanup. Cross-run sweep happens via the scope sweep above
    # (deleting the scope orphans the user; it remains revokable manually).
    return 0


# --- Scenarios -----------------------------------------------------------

@scenario("api_keys")
def scenario_api_keys(s: Session) -> None:
    """End-to-end API-key lifecycle.

    Steps:
      1. POST /api/auth/users        -> create API-key user (type=9).
      2. POST /api/3/api_keys        -> bind scope with name=live-<run>-<slug>.
      3. GET  /api/3/api_keys/{uuid} -> read scope back.
      4. PUT  /api/auth/users        -> DEACTIVATE, then ACTIVATE.
      5. PUT  /api/auth/users        -> REGENERATE (api_key_validity=5).
      6. Cleanup: DELETE scope, REVOKE user.
    """
    print("[api_keys] step 1: create API-key user")
    _, user = s.call("POST", "/api/auth/users", want=(200, 201),
                     json={"type": 9, "status": 1, "api_key_validity": 1})
    user = user or {}
    user_id = user.get("uuid")
    assert user_id, f"no uuid in create response: {user}"
    s.track("api_key_user", user_id)
    print(f"  user uuid = {user_id}")

    print("[api_keys] step 2: bind scope")
    _, scope = s.call("POST", "/api/3/api_keys", want=(200, 201),
                      json={"name": s.live_name("apikey"), "roles": [], "teams": [], "userId": user_id})
    scope = scope or {}
    scope_uuid = scope.get("uuid") or scope.get("@id", "").rsplit("/", 1)[-1]
    assert scope_uuid, f"no scope uuid: {scope}"
    s.track("api_key_scope", scope_uuid)
    print(f"  scope uuid = {scope_uuid}")

    print("[api_keys] step 3: read scope back")
    s.call("GET", "/api/3/api_keys/{uuid}", want=200, path_params={"uuid": scope_uuid})

    print("[api_keys] step 3b: update scope (rename)")
    s.call("PUT", "/api/3/api_keys/{uuid}", want=200, path_params={"uuid": scope_uuid},
           json={"name": s.live_name("apikey-renamed"), "roles": [], "teams": [], "userId": user_id})

    print("[api_keys] step 3c: bulk fetch user record")
    s.call("POST", "/api/auth/query/users", want=200,
           json={"users": [user_id], "show_api_key": False})

    print("[api_keys] step 3d: read user by uuid")
    s.call("GET", "/api/auth/users", want=200, params={"uuid": user_id})

    print("[api_keys] step 4: deactivate + activate")
    s.call("PUT", "/api/auth/users", want=200,
           json={"uuid": user_id, "key_type": "API_KEY", "operation": "DEACTIVATE"})
    s.call("PUT", "/api/auth/users", want=200,
           json={"uuid": user_id, "key_type": "API_KEY", "operation": "ACTIVATE"})

    print("[api_keys] step 5: regenerate")
    s.call("PUT", "/api/auth/users", want=200,
           json={"uuid": user_id, "key_type": "API_KEY", "operation": "REGENERATE",
                 "api_key_validity": 5})

    print("[api_keys] step 6: cleanup")
    s.request("DELETE", f"/api/3/api_keys/{scope_uuid}")
    s.request("PUT", "/api/auth/users",
              json={"uuid": user_id, "key_type": "API_KEY", "operation": "REVOKE"})


@scenario("smoke")
def scenario_smoke(s: Session) -> None:
    """Read-only smoke calls to populate response examples on stable ops.

    No record creation — every call is either a GET or a side-effect-free POST.
    """
    print("[smoke] credential login (captures /auth/authenticate)")
    # Mint a fresh JWT explicitly so the operation gets recorded under the
    # current auth mode. Session creds already work; this just publishes
    # the example shape.
    user = os.environ.get("FSR_USERNAME")
    pw = os.environ.get("FSR_PASSWORD")
    if user and pw:
        s.call("POST", "/auth/authenticate", want=200,
               json={"credentials": {"loginid": user, "password": pw}})

    print("[smoke] system identity (public + auth-required)")
    s.call("GET", "/api/version", want=200)
    s.call("GET", "/api/auth/cluster/health", want=(200, 403))
    # Pass the documented `param=license_details` + `node_id=SELF` so the
    # JWT call gets a real 200 (the unparameterized form returns 400 on this
    # build). API-KEY remains 403 - that's a real auth gate, not a bug.
    s.call("GET", "/api/auth/license", want=(200, 400, 403),
           params={"param": "license_details", "node_id": "SELF"})

    print("[smoke] permissions + actor")
    s.call("GET", "/api/permissions/current", want=200)
    s.call("GET", "/api/3/actors/current", want=200)

    print("[smoke] audit gateway catalog")
    s.call("GET", "/api/gateway/audit/operations", want=200)

    print("[smoke] access management read")
    s.call("GET", "/api/3/roles", want=200, params={"$limit": 2})
    s.call("GET", "/api/3/teams", want=200, params={"$limit": 2})
    # api_keys is JWT-only on the box we tested - record coverage either way.
    s.call("GET", "/api/3/api_keys", want=(200, 403), params={"$limit": 2})

    print("[smoke] picklist taxonomy")
    _, pln = s.call("GET", "/api/3/picklist_names", want=200, params={"$limit": 1})
    members = (pln or {}).get("hydra:member") or []
    if members:
        pln_uuid = members[0].get("uuid") or (members[0].get("@id", "").rsplit("/", 1)[-1])
        if pln_uuid:
            s.call("GET", "/api/3/picklist_names/{uuid}", want=200,
                   path_params={"uuid": pln_uuid})
            # Drill into one picklist value owned by this taxonomy.
            r = s.request("GET", f"/api/3/picklists?listName=/api/3/picklist_names/{pln_uuid}&$limit=1")
            if r.ok:
                pmem = (r.json() or {}).get("hydra:member") or []
                if pmem:
                    pk_uuid = pmem[0].get("uuid") or (pmem[0].get("@id", "").rsplit("/", 1)[-1])
                    if pk_uuid:
                        s.call("GET", "/api/3/picklists/{uuid}", want=200,
                               path_params={"uuid": pk_uuid})

    print("[smoke] feature access + auth config read")
    s.call("GET", "/api/product/feature-access", want=200)
    # API-KEY auth can't read auth config; accept 403 so coverage is recorded.
    s.call("GET", "/api/auth/config", want=(200, 403), params={"section": "API-KEYS"})

    print("[smoke] metadata catalogs")
    s.call("GET", "/api/3/model_metadatas", want=200, params={"$limit": 5})
    s.call("GET", "/api/3/contexts/{shortName}", want=200, path_params={"shortName": "Alert"})
    s.call("GET", "/api/3/docs.jsonld", want=200)

    print("[smoke] workflows list + detail")
    _, wf_list = s.call("GET", "/api/wf/api/workflows/", want=200,
                        params={"parent_wf__isnull": "True", "ordering": "-modified", "limit": 1})
    members = (wf_list or {}).get("hydra:member") or (wf_list or {}).get("results") or []
    if members:
        first = members[0]
        # `@id` is `/wf/api/workflows/<pk>/` (trailing slash). Trim then split.
        raw = first.get("@id") or str(first.get("id") or "")
        pk = raw.rstrip("/").rsplit("/", 1)[-1]
        if pk:
            s.call("GET", "/api/wf/api/workflows/{pk}/", want=200, path_params={"pk": pk})
    else:
        print("  (no workflow runs to fetch detail for)")

    print("[smoke] workflow count (slashed form)")
    s.call("GET", "/api/wf/api/workflows/count/", want=200,
           params={"format": "json", "logs": "all"})

    print("[smoke] historical workflow list + detail")
    _, hist_list = s.call("GET", "/api/wf/api/historical-workflows/", want=200,
                          params={"format": "json", "limit": 1, "ordering": "-created"})
    members = (hist_list or {}).get("hydra:member") or []
    if members:
        raw = members[0].get("@id") or ""
        pk = raw.rstrip("/").rsplit("/", 1)[-1]
        if pk:
            s.call("GET", "/api/wf/api/historical-workflows/{pk}/", want=200,
                   path_params={"pk": pk}, params={"format": "json"})
    else:
        print("  (no historical runs yet)")

    print("[smoke] workflow log_list (empty task_id ok)")
    s.call("POST", "/api/wf/api/workflows/log_list/", want=200,
           params={"format": "json", "limit": 2, "offset": 0, "ordering": "-modified",
                   "page": 1, "parent_wf__isnull": "True"},
           json={})

    print("[smoke] workflow_logs combined query")
    s.call("POST", "/api/wf/api/query/workflow_logs/", want=200,
           params={"logs": "all"},
           json={"logic": "AND", "limit": 2,
                 "sort": [{"field": "modified", "direction": "desc"}],
                 "filters": [{"field": "status", "operator": "eq", "value": "finished"}]})

    print("[smoke] jinja render + manual-input list")
    s.call("POST", "/api/wf/api/jinja-editor/", want=200,
           json={"template": "{{ name | upper }}", "values": {"name": "alert-001"}})
    s.call("POST", "/api/wf/api/manual-wf-input/list_wfinput/", want=200, json={})

    print("[smoke] generic record fetch")
    # Pull an alerts list to find a real uuid, then exercise the generic
    # /api/3/{collection}/{uuid} template. Skip cleanly if no alerts exist.
    r = s.request("GET", "/api/3/alerts?$limit=1")
    if r.ok:
        try:
            members = r.json().get("hydra:member", [])
        except ValueError:
            members = []
        if members:
            uuid_ = members[0].get("uuid") or (members[0].get("@id", "").rsplit("/", 1)[-1])
            if uuid_:
                s.call("GET", "/api/3/{collection}/{uuid}", want=200,
                       path_params={"collection": "alerts", "uuid": uuid_})


@scenario("queries")
def scenario_queries(s: Session) -> None:
    """Exercise the Query API end-to-end.

    Steps:
      1. POST /api/query/alerts          -> ad-hoc query (read-only).
      2. POST /api/3/query_objects       -> persist a saved query (live-* name).
      3. POST /api/query/alerts/{qid}    -> execute the persisted query.
      4. POST /api/search                -> global ES search (may return 500
         on some 7.6 builds; accept that here so coverage still records).
      5. Cleanup: DELETE the persisted query.
    """
    print("[queries] step 1: ad-hoc query on alerts")
    s.call("POST", "/api/query/{collection}", want=200,
           path_params={"collection": "alerts"},
           params={"$limit": 1, "$page": 1},
           json={
               "logic": "AND",
               "filters": [
                   {"field": "status.itemValue", "operator": "neq", "value": "Closed"},
               ],
               "sort": [{"field": "createDate", "direction": "desc"}],
           })

    print("[queries] step 2: persist a saved query (UserQuery)")
    # The saved-query store is `/api/3/user_queries` (UserQuery type). A
    # `models` IRI to the target collection's model_metadata record is required.
    model_iri = None
    r = s.request("GET", "/api/3/model_metadatas?module=alerts&$limit=1")
    if r.ok:
        m = r.json().get("hydra:member", [])
        if m:
            model_iri = m[0].get("@id")
    qid = None
    if model_iri:
        _, qobj = s.call("POST", "/api/3/user_queries", want=(200, 201),
                         json={
                             "name": s.live_name("savedq"),
                             "models": model_iri,
                             "query": {
                                 "logic": "AND",
                                 "filters": [
                                     {"field": "status.itemValue", "operator": "neq", "value": "Closed"},
                                 ],
                                 "limit": 5,
                             },
                         })
        qobj = qobj or {}
        qid = qobj.get("uuid") or (qobj.get("@id", "").rsplit("/", 1)[-1])
        if qid:
            s.track("user_query", qid)
            print(f"  saved query uuid = {qid}")

    if qid:
        # The execute path documented in build_curated.py
        # (`POST /api/query/{collection}/{queryId}`) returns 404 on this 7.6.x
        # build under several collection slugs. Capture the observation so the
        # doc surfaces "tested -> 404" instead of claiming success.
        print("[queries] step 3: execute persisted query (best-effort)")
        s.call("POST", "/api/query/{collection}/{queryId}",
               want=(200, 400, 404),
               path_params={"collection": "alerts", "queryId": qid},
               json={"$limit": 1, "$page": 1})

    print("[queries] step 4: /api/search (may 500 on 7.6.x)")
    s.call("POST", "/api/search", want=(200, 400, 500),
           json={"q": "live-test", "index": ["alerts", "incidents"], "size": 5})

    if qid:
        print("[queries] step 5: cleanup saved query")
        r = s.request("DELETE", f"/api/3/user_queries/{qid}")
        print(f"  DELETE saved query -> {r.status_code}")


@scenario("connector_lifecycle")
def scenario_connector_lifecycle(s: Session) -> None:
    """End-to-end connector flow against a real .tgz.

    Steps:
      1. POST /api/3/solutionpacks/install (multipart .tgz) -> install hello-world.
      2. Poll /api/integration/connectors/ until the connector is `installed`.
      3. POST /api/integration/configuration/  -> create a config with live-* name.
      4. POST /api/integration/execute/        -> run reverse_text action.
      5. POST /api/integration/connectors/healthcheck/ -> verify health.
      6. Cleanup: DELETE config, then uninstall connector (probe endpoint live).
    """
    import os as _os
    NAME = "hello-world"
    VERSION = "1.0.4"
    # Vendored at tests/fixtures/; override via env for a different build.
    TGZ = _os.environ.get("FSR_HELLO_TGZ", str(ROOT / "tests" / "fixtures" / f"{NAME}-{VERSION}.tgz"))
    assert _os.path.exists(TGZ), f"connector tgz missing: {TGZ}"

    print(f"[connector] step 1: upload + install {NAME} {VERSION}")
    with open(TGZ, "rb") as f:
        r, inst = s.call(
            "POST", "/api/3/solutionpacks/install", want=(200, 201),
            params={"$type": "connector", "$replace": "true"},
            files={"file": (_os.path.basename(TGZ), f, "application/gzip")},
            timeout=180,
        )
    inst = inst or {}
    connector_id = inst.get("id")
    print(f"  installed -> id={connector_id} status={inst.get('status')!r}")
    assert connector_id, f"no connector id in install response: {inst}"
    s.track("connector", str(connector_id))

    print("[connector] step 2: list connectors + configurations (read-only)")
    s.call("GET", "/api/integration/connectors/", want=200, params={"name": NAME})
    # Connector-detail (operations + configurations) - the discovery endpoint
    # for what to pass to /api/integration/execute/. Body must be `{}`; empty
    # body returns 415 and GET returns a "use POST" 200 envelope.
    s.call("POST", "/api/integration/connectors/{id}/", want=200,
           path_params={"id": connector_id}, json={})
    # `page_size` (not `limit`) is the pagination param for the integration
    # collections — Django REST style, distinct from the Hydra `limit` used
    # under `/api/3/`. Capping to 1 keeps the captured example readable.
    s.call("GET", "/api/integration/configuration/", want=200, params={"page_size": 1})

    print("[connector] step 3: create configuration")
    # `agent` is intentionally omitted — it's only required when delegating
    # execution to a remote agent. Self-agent (default) is used implicitly.
    config_name = s.live_name("hwcfg")
    _, cfg = s.call("POST", "/api/integration/configuration/", want=(200, 201),
                    json={"name": config_name, "connector": connector_id,
                          "config": {"default_greeting": "Hello", "salutation": "Mr."},
                          "default": False, "status": 1, "teams": []})
    cfg = cfg or {}
    cfg_uuid = cfg.get("config_id")
    assert cfg_uuid, f"no config_id in create response: {cfg}"
    s.track("connector_config", cfg_uuid)
    print(f"  config_id = {cfg_uuid}  (DB id={cfg.get('id')})")

    print("[connector] step 4: execute reverse_text action")
    r, body = s.call("POST", "/api/integration/execute/",
                     json={"connector": NAME, "version": VERSION,
                           "operation": "reverse_text", "config": cfg_uuid,
                           "params": {"input_text": "live-test"}})
    print(f"  execute -> {r.status_code}  {str(body)[:200]}")

    print("[connector] step 5: healthcheck (GET form using existing config)")
    r, body = s.call("GET",
                     "/api/integration/connectors/healthcheck/{name}/{version}/",
                     path_params={"name": NAME, "version": VERSION},
                     params={"config": cfg_uuid})
    print(f"  healthcheck GET -> {r.status_code}  {str(body)[:200]}")

    # NOTE: POST /api/integration/connectors/healthcheck/ (the inline-body
    # form) appears to be unrouted on FSR 7.6.x - every body shape probed
    # returned 404 with an empty message. The GET form (above) is the only
    # working variant. The spec entry for the POST form was removed.

    print("[connector] step 6: cleanup")
    # Config DELETE requires uuid (config_id) + trailing slash. Without it the
    # route hits an HMAC-gated handler returning a misleading 403.
    r, _ = s.call("DELETE", "/api/integration/configuration/{config_id}/",
                  path_params={"config_id": cfg_uuid})
    print(f"  DELETE config -> {r.status_code}")
    r, _ = s.call("DELETE", "/api/integration/connectors/{id}/",
                  path_params={"id": connector_id})
    print(f"  DELETE connector -> {r.status_code}")


@scenario("alerts_crud")
def scenario_alerts_crud(s: Session) -> None:
    """Full alert lifecycle against the dedicated `/api/3/alerts` routes.

    Covers the typed-collection CRUD endpoints distinct from the generic
    `/api/3/{collection}` form: list, create, read-by-uuid, update, delete.
    """
    print("[alerts] step 1: list")
    s.call("GET", "/api/3/alerts", want=200, params={"$limit": 2})

    print("[alerts] step 2: resolve picklist IRIs for severity + status")
    # Both severity and status point at picklist values, not free strings.
    # Picklist names on FSR 7.6.x are PascalCase: `Severity`, `AlertStatus`.
    def _first_value(pln_id: str) -> str | None:
        rr = s.request("GET", f"/api/3/picklists?listName={pln_id}&$limit=1")
        if not rr.ok:
            return None
        pmem = (rr.json() or {}).get("hydra:member") or []
        return pmem[0].get("@id") if pmem else None

    sev_iri = status_iri = None
    r = s.request("GET", "/api/3/picklist_names?$limit=200")
    if r.ok:
        for m in (r.json().get("hydra:member") or []):
            name = (m.get("name") or "")
            if name == "Severity" and not sev_iri:
                sev_iri = _first_value(m.get("@id"))
            elif name == "AlertStatus" and not status_iri:
                status_iri = _first_value(m.get("@id"))
    assert sev_iri and status_iri, f"could not resolve picklist IRIs (sev={sev_iri}, status={status_iri})"

    print("[alerts] step 3: create")
    alert_name = s.live_name("alert")
    body = {"name": alert_name, "source": "live-test", "severity": sev_iri, "status": status_iri}
    _, created = s.call("POST", "/api/3/alerts", want=(200, 201), json=body)
    created = created or {}
    alert_uuid = created.get("uuid") or (created.get("@id", "").rsplit("/", 1)[-1])
    assert alert_uuid, f"no uuid in create response: {created}"
    s.track("alert", alert_uuid)
    print(f"  created alert {alert_uuid}")

    print("[alerts] step 4: read by uuid")
    s.call("GET", "/api/3/alerts/{uuid}", want=200, path_params={"uuid": alert_uuid})

    print("[alerts] step 5: update (PUT)")
    s.call("PUT", "/api/3/alerts/{uuid}", want=200, path_params={"uuid": alert_uuid},
           json={"description": "updated by live_test"})

    print("[alerts] step 6: delete")
    r, _ = s.call("DELETE", "/api/3/alerts/{uuid}", want=(200, 204),
                  path_params={"uuid": alert_uuid})
    print(f"  DELETE alert -> {r.status_code}")


@scenario("license_checks")
def scenario_license_checks(s: Session) -> None:
    """Non-destructive license API coverage.

    Only the read paths are exercised - deploy_license / get_info both
    require a real license_key and aren't safe to probe blindly against a
    live appliance.
    """
    print("[license] step 1: GET /api/auth/license (param=license_details)")
    s.call("GET", "/api/auth/license", want=(200, 400, 403),
           params={"param": "license_details", "node_id": "SELF"})

    print("[license] step 2: POST /api/public/license (action=get_status)")
    # Unauthenticated endpoint; nodeId is optional - omitting it returns the
    # cluster-wide deployment status. Drop auth temporarily so the observation
    # reflects the public nature of the endpoint.
    saved = s.headers.pop("Authorization", None)
    try:
        s.call("POST", "/api/public/license", want=200,
               json={"action": "get_status"})
    finally:
        if saved is not None:
            s.headers["Authorization"] = saved


@scenario("bulk_crud")
def scenario_bulk_crud(s: Session) -> None:
    """Exercise the working bulk endpoints against `alerts`.

    On FSR 7.6.x, `POST /api/3/insert/{moduleType}`, `PUT /api/3/update/{moduleType}`,
    and `DELETE /api/3/delete/{moduleType}` consistently 500 (TypeError /
    HttpException) for every body shape probed - they're documented but
    skipped here. The two endpoints below DO work.
    """
    # Resolve severity + status IRIs (same as alerts_crud).
    def _first_value(pln_id: str) -> str | None:
        r = s.request("GET", f"/api/3/picklists?listName={pln_id}&$limit=1")
        if not r.ok:
            return None
        m = (r.json() or {}).get("hydra:member") or []
        return m[0].get("@id") if m else None
    sev_iri = status_iri = None
    r = s.request("GET", "/api/3/picklist_names?$limit=200")
    if r.ok:
        for m in (r.json().get("hydra:member") or []):
            if m.get("name") == "Severity" and not sev_iri:
                sev_iri = _first_value(m["@id"])
            elif m.get("name") == "AlertStatus" and not status_iri:
                status_iri = _first_value(m["@id"])
    assert sev_iri and status_iri

    print("[bulk] step 1: upsert (single object) on alerts")
    _, created = s.call("POST", "/api/3/upsert/{moduleType}", want=(200, 201),
                        path_params={"moduleType": "alerts"},
                        json={"name": s.live_name("upsert"), "source": "live_test",
                              "severity": sev_iri, "status": status_iri})
    if created:
        s.track("alert", (created.get("@id") or "").rsplit("/", 1)[-1])

    print("[bulk] step 2: bulkupsert (array) on alerts")
    # bulkupsert returns invalid-credentials under API-KEY auth on this build;
    # accept that as a captured outcome rather than failing the scenario.
    s.call("POST", "/api/3/bulkupsert/{moduleType}", want=(200, 201, 500),
           path_params={"moduleType": "alerts"},
           json=[{"name": s.live_name("bulkupsert"), "source": "live_test",
                  "severity": sev_iri, "status": status_iri}])


@scenario("audit_query")
def scenario_audit_query(s: Session) -> None:
    """Audit gateway: query / count / fetch-by-id. All read-only."""
    print("[audit] step 1: query recent activities")
    _, page = s.call("POST", "/api/gateway/audit/activities", want=200,
                     json={"limit": 2, "logic": "AND", "filters": []})
    print("[audit] step 2: count")
    s.call("POST", "/api/gateway/audit/activities/count", want=200,
           json={"logic": "AND", "filters": []})
    print("[audit] step 3: fetch one activity by auditId")
    content = (page or {}).get("content") or []
    if content:
        audit_id = content[0].get("id") or content[0].get("auditId")
        if audit_id:
            s.call("GET", "/api/gateway/audit/activities/{auditId}", want=(200, 404),
                   path_params={"auditId": str(audit_id)})


@scenario("files_upload")
def scenario_files_upload(s: Session) -> None:
    """Multipart upload to /api/3/files. Cleanup not needed (uploads expire)."""
    print("[files] step 1: upload a small text fixture")
    s.call("POST", "/api/3/files", want=(200, 201),
           files={"file": ("live-test.txt", b"live-test payload", "text/plain")})


@scenario("rbac_and_generic_crud")
def scenario_rbac_and_generic_crud(s: Session) -> None:
    """Exercise roles + teams POST, plus the generic /api/3/{collection} CRUD template.

    The generic-template calls capture observations under the literal
    `/api/3/{collection}` / `/{collection}/{uuid}` keys - distinct from the
    typed-collection forms (`/api/3/roles`, `/api/3/teams`).
    """
    role_name = s.live_name("role")
    team_name = s.live_name("team")

    print("[rbac] step 1: POST /api/3/roles (typed)")
    _, role = s.call("POST", "/api/3/roles", want=(200, 201),
                     json={"name": role_name, "description": "live_test role"})
    role = role or {}
    role_uuid = role.get("uuid") or (role.get("@id", "").rsplit("/", 1)[-1])
    if role_uuid:
        s.track("role", role_uuid)

    print("[rbac] step 2a: GET /api/3/{collection} (generic listing)")
    s.call("GET", "/api/3/{collection}", want=200,
           path_params={"collection": "teams"}, params={"$limit": 1})

    print("[rbac] step 2b: POST /api/3/teams (typed)")
    second_team = s.live_name("team2")
    _, team2 = s.call("POST", "/api/3/teams", want=(200, 201),
                      json={"name": second_team, "description": "live_test team (typed)"})
    team2 = team2 or {}
    team2_uuid = team2.get("uuid") or (team2.get("@id", "").rsplit("/", 1)[-1])
    if team2_uuid:
        # Cleanup via raw request - the generic DELETE template gets captured below.
        s.request("DELETE", f"/api/3/teams/{team2_uuid}")

    print("[rbac] step 2c: POST /api/3/{collection} (generic, collection=teams)")
    _, team = s.call("POST", "/api/3/{collection}", want=(200, 201),
                     path_params={"collection": "teams"},
                     json={"name": team_name, "description": "live_test team"})
    team = team or {}
    team_uuid = team.get("uuid") or (team.get("@id", "").rsplit("/", 1)[-1])
    assert team_uuid, f"no uuid in team create response: {team}"
    s.track("team", team_uuid)

    print("[rbac] step 3: PUT /api/3/{collection}/{uuid} (rename via generic)")
    s.call("PUT", "/api/3/{collection}/{uuid}", want=200,
           path_params={"collection": "teams", "uuid": team_uuid},
           json={"description": "renamed by live_test"})

    print("[rbac] step 4: DELETE /api/3/{collection}/{uuid} (generic)")
    r, _ = s.call("DELETE", "/api/3/{collection}/{uuid}", want=(200, 204),
                  path_params={"collection": "teams", "uuid": team_uuid})
    print(f"  DELETE team -> {r.status_code}")

    # Cleanup the role via a raw call (no observation needed - generic DELETE
    # was already captured above).
    if role_uuid:
        s.request("DELETE", f"/api/3/roles/{role_uuid}")


def _first_picklist_value(s: Session, list_name: str) -> str | None:
    """Resolve the IRI of the first picklist value under a given listName."""
    r = s.request("GET", "/api/3/picklist_names", params={"name": list_name, "$limit": 1})
    if not r.ok:
        return None
    members = (r.json() or {}).get("hydra:member") or []
    if not members:
        return None
    pln_iri = members[0].get("@id")
    rr = s.request("GET", "/api/3/picklists",
                   params={"listName": pln_iri, "$limit": 1})
    if not rr.ok:
        return None
    pmem = (rr.json() or {}).get("hydra:member") or []
    return pmem[0].get("@id") if pmem else None


@scenario("incidents_crud")
def scenario_incidents_crud(s: Session) -> None:
    """Full incident lifecycle: list, create with picklists, read, update, delete."""
    print("[incidents] step 1: list")
    s.call("GET", "/api/3/incidents", want=200, params={"$limit": 2})

    print("[incidents] step 2: resolve severity picklist IRI")
    sev_iri = _first_picklist_value(s, "Severity")
    assert sev_iri, "could not resolve Severity picklist"

    print("[incidents] step 3: create")
    body = {"name": s.live_name("incident"), "source": "live-test", "severity": sev_iri}
    _, created = s.call("POST", "/api/3/incidents", want=(200, 201), json=body)
    created = created or {}
    inc_uuid = created.get("uuid") or (created.get("@id", "").rsplit("/", 1)[-1])
    assert inc_uuid, f"no uuid in incident create response: {created}"
    s.track("incident", inc_uuid)

    print("[incidents] step 4: read by uuid")
    s.call("GET", "/api/3/incidents/{uuid}", want=200, path_params={"uuid": inc_uuid})

    print("[incidents] step 5: update (PUT)")
    s.call("PUT", "/api/3/incidents/{uuid}", want=200, path_params={"uuid": inc_uuid},
           json={"description": "updated by live_test"})

    print("[incidents] step 6: delete")
    r, _ = s.call("DELETE", "/api/3/incidents/{uuid}", want=(200, 204),
                  path_params={"uuid": inc_uuid})
    print(f"  DELETE incident -> {r.status_code}")


@scenario("tasks_crud")
def scenario_tasks_crud(s: Session) -> None:
    """Full task lifecycle: list, create with priority picklist, read, update, delete."""
    print("[tasks] step 1: list")
    s.call("GET", "/api/3/tasks", want=200, params={"$limit": 2})

    print("[tasks] step 2: resolve TaskPriority picklist IRI")
    pri_iri = (_first_picklist_value(s, "TaskPriority")
               or _first_picklist_value(s, "Priority"))
    assert pri_iri, "could not resolve Task priority picklist"

    print("[tasks] step 3: create")
    body = {"name": s.live_name("task"),
            "description": "live_test task",
            "priority": pri_iri}
    _, created = s.call("POST", "/api/3/tasks", want=(200, 201), json=body)
    created = created or {}
    task_uuid = created.get("uuid") or (created.get("@id", "").rsplit("/", 1)[-1])
    assert task_uuid, f"no uuid in task create response: {created}"
    s.track("task", task_uuid)

    print("[tasks] step 4: read by uuid")
    s.call("GET", "/api/3/tasks/{uuid}", want=200, path_params={"uuid": task_uuid})

    print("[tasks] step 5: update (PUT)")
    s.call("PUT", "/api/3/tasks/{uuid}", want=200, path_params={"uuid": task_uuid},
           json={"description": "updated by live_test"})

    print("[tasks] step 6: delete")
    r, _ = s.call("DELETE", "/api/3/tasks/{uuid}", want=(200, 204),
                  path_params={"uuid": task_uuid})
    print(f"  DELETE task -> {r.status_code}")


@scenario("comments_crud")
def scenario_comments_crud(s: Session) -> None:
    """Comment surface: both the parent-scoped sub-collection POST and the
    generic `/api/3/comments` CRUD path.

    Creates a temporary parent incident, posts one comment under
    `/api/3/incidents/{recordId}/comments`, another via `POST /api/3/comments`,
    reads each, updates, and deletes.
    """
    print("[comments] setup: create parent incident")
    sev_iri = _first_picklist_value(s, "Severity")
    assert sev_iri, "could not resolve Severity picklist for parent incident"
    _, parent = s.call("POST", "/api/3/incidents", want=(200, 201),
                       json={"name": s.live_name("comment-parent"),
                             "source": "live-test", "severity": sev_iri})
    parent = parent or {}
    parent_uuid = parent.get("uuid") or (parent.get("@id", "").rsplit("/", 1)[-1])
    assert parent_uuid, "no parent incident uuid"
    s.track("incident", parent_uuid)
    parent_iri = f"/api/3/incidents/{parent_uuid}"

    marker = s.live_name("comment")  # ensures the sweeper can find it

    print("[comments] step 1: GET /api/3/{module}/{recordId}/comments (parent-scoped list)")
    s.call("GET", "/api/3/{module}/{recordId}/comments", want=200,
           path_params={"module": "incidents", "recordId": parent_uuid},
           params={"$limit": 5})

    print("[comments] step 2: POST /api/3/comments (linked via incidents IRI)")
    _, gen = s.call("POST", "/api/3/comments", want=(200, 201),
                    json={"content": f"<p>{marker} linked to incident</p>",
                          "incidents": [parent_iri]})
    gen = gen or {}
    gen_uuid = gen.get("uuid") or (gen.get("@id", "").rsplit("/", 1)[-1])
    assert gen_uuid, f"no uuid in comment create response: {gen}"
    s.track("comment", gen_uuid)

    print("[comments] step 4: GET /api/3/comments/{uuid}")
    s.call("GET", "/api/3/comments/{uuid}", want=200, path_params={"uuid": gen_uuid})

    print("[comments] step 5: PUT /api/3/comments/{uuid} (mark important)")
    s.call("PUT", "/api/3/comments/{uuid}", want=200, path_params={"uuid": gen_uuid},
           json={"isImportant": True})

    print("[comments] step 6: DELETE /api/3/comments/{uuid}")
    r, _ = s.call("DELETE", "/api/3/comments/{uuid}", want=(200, 204),
                  path_params={"uuid": gen_uuid})
    print(f"  DELETE comment -> {r.status_code}")

    s.request("DELETE", f"/api/3/incidents/{parent_uuid}")


@scenario("taxii_and_feed_ingest")
def scenario_taxii_and_feed_ingest(s: Session) -> None:
    """TAXII 2.1 server reads + the `/api/ingest-feeds/*` POST family.

    TAXII calls walk: root -> collections -> single collection -> objects ->
    one-object -> manifest. UUIDs come from the live collections list so the
    scenario survives appliance-to-appliance differences.

    The ingest-feeds POSTs accept either 200 (real ingest) or 400 (schema
    rejection on the safe stub payload). Both outcomes record per-auth
    coverage; failure bodies are intentionally not persisted (see `_scrub`'s
    contract -- only <400 bodies are kept).
    """
    print("[taxii] root + collections")
    s.call("GET", "/api/taxii/1/", want=200)
    _, cols = s.call("GET", "/api/taxii/1/collections/", want=200)
    collections = (cols or {}).get("collections") or []
    assert collections, "no TAXII collections returned"
    cid = collections[0].get("uuid") or collections[0].get("id")
    assert cid, "no uuid on first TAXII collection"

    print(f"[taxii] single collection {cid}")
    s.call("GET", "/api/taxii/1/collections/{uuid}/", want=200,
           path_params={"uuid": cid})

    print("[taxii] objects + manifest")
    s.call("GET", "/api/taxii/1/collections/{uuid}/objects/", want=200,
           path_params={"uuid": cid}, params={"limit": 2})
    # Use a synthetic STIX id; an empty `{totalItems, objects: []}` envelope
    # is the expected shape whether or not the id matches.
    stix_id = "indicator--11111111-1111-1111-1111-111111111111"
    s.call("GET", "/api/taxii/1/collections/{uuid}/objects/{stixId}/", want=200,
           path_params={"uuid": cid, "stixId": stix_id})
    s.call("GET", "/api/taxii/1/collections/{uuid}/manifest/", want=200,
           path_params={"uuid": cid}, params={"limit": 2})

    # FortiSOAR's TAXII server is read-only on this build: POST returns 404
    # (no route), not 405 — so we don't claim a POST operation in the spec.

    print("[feed-ingest] sibling POSTs (observables / stix-bundle / threatintel / reputation)")
    # The existing `/api/ingest-feeds/indicators` is exercised elsewhere; the
    # four siblings below have undocumented payload schemas, so we accept 400
    # alongside 200 to record per-auth coverage without false-failing the run.
    s.call("POST", "/api/ingest-feeds/observables", want=(200, 400),
           json=[{"value": "198.51.100.10", "type": "IP Address",
                  "source": "live-test"}])
    s.call("POST", "/api/ingest-feeds/stix-bundle", want=(200, 400),
           json={
               "type": "bundle",
               "id": "bundle--00000000-0000-0000-0000-000000000001",
               "objects": [{
                   "type": "indicator", "spec_version": "2.1",
                   "id": "indicator--33333333-3333-3333-3333-333333333333",
                   "created": "2025-01-01T00:00:00.000Z",
                   "modified": "2025-01-01T00:00:00.000Z",
                   "pattern": "[ipv4-addr:value = '198.51.100.20']",
                   "pattern_type": "stix",
                   "valid_from": "2025-01-01T00:00:00Z",
               }],
           })
    s.call("POST", "/api/ingest-feeds/threatintel", want=(200, 400),
           json=[{"name": s.live_name("ti-record"), "source": "live-test"}])
    s.call("POST", "/api/ingest-feeds/reputation", want=(200, 400),
           json=[{"value": "198.51.100.30", "type": "IP Address",
                  "reputation": "Suspicious", "source": "live-test"}])


# --- CLI -----------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep-only", action="store_true", help="Clean up leftover live-* records and exit.")
    ap.add_argument("--scenario", action="append", help="Run only the named scenario(s). Defaults to all.")
    ap.add_argument("--no-presweep", action="store_true", help="Skip the startup sweep.")
    args = ap.parse_args()

    s = open_session()
    print(f"base: {s.base}")
    print(f"run id: {s.run_id}")

    if not args.no_presweep:
        print("--- pre-sweep ---")
        n = sweep(s)
        print(f"  removed {n} leftover live-* record(s)")

    if args.sweep_only:
        return 0

    targets = args.scenario or list(SCENARIOS.keys())
    failed: list[str] = []
    print(f"auth modes: {list(s.auth_modes)}")
    for name in targets:
        fn = SCENARIOS.get(name)
        if not fn:
            print(f"  unknown scenario: {name}", file=sys.stderr)
            failed.append(name)
            continue
        for mode in list(s.auth_modes):
            s.set_auth(mode)
            print(f"--- scenario: {name} (auth={mode}) ---")
            t0 = time.time()
            try:
                fn(s)
                print(f"  ok ({(time.time() - t0) * 1000:.0f} ms)")
            except Exception as exc:
                print(f"  FAILED ({mode}): {exc}", file=sys.stderr)
                failed.append(f"{name}[{mode}]")
            # Sweep between auth runs so the next run starts clean.
            sweep(s)

    print("--- post-sweep ---")
    n = sweep(s)
    print(f"  removed {n} record(s)")

    # Fill in `gated_upstream` markers: if an op was touched under one auth
    # mode but not another, the other auth was blocked upstream (the scenario
    # aborted before reaching this call). For documentation purposes we treat
    # that as "unavailable under that auth" — a caller using that mode cannot
    # practically reach this endpoint via the documented flow.
    today = _dt.date.today().isoformat()
    for op_key, op_rec in s.observations.items():
        by_auth = op_rec.setdefault("by_auth", {})
        for mode in s.auth_modes:
            if mode not in by_auth:
                by_auth[mode] = {
                    "response_status": None,
                    "gated_upstream": True,
                    "captured_at": today,
                }

    if s.observations:
        OBSERVATIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Merge two levels deep: prior observations for ops we didn't touch
        # this run are preserved, and prior per-auth records for ops we
        # touched under one mode but not the other are also kept.
        prior: dict = {}
        if OBSERVATIONS_PATH.exists():
            try:
                prior = json.loads(OBSERVATIONS_PATH.read_text())
            except json.JSONDecodeError:
                prior = {}
        for op_key, op_rec in s.observations.items():
            existing = prior.setdefault(op_key, {"by_auth": {}})
            existing.setdefault("by_auth", {}).update(op_rec.get("by_auth", {}))
        OBSERVATIONS_PATH.write_text(json.dumps(prior, indent=2, sort_keys=True))
        print(f"--- observations: wrote {len(s.observations)} op(s) "
              f"(total {len(prior)}) to {OBSERVATIONS_PATH.relative_to(ROOT)} ---")

    if failed:
        print(f"\n{len(failed)} scenario(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
