"""Live, stateful API smoke tests against a real FortiSOAR appliance.

Complements `verify_curated.py` (read-only, per-op) by exercising end-to-end
workflows that involve creating records, calling dependent endpoints with
the real uuids, and then cleaning up.

**Naming contract.** Every record we create has its `name` (or equivalent
identifier) prefixed with `LIVE_PREFIX` ("live-"). On startup we sweep any
records matching that prefix -- so a crashed prior run gets cleaned up
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
from pyfsr.pagination import extract_members

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
# `live-<run_id>-<slug>` shows up wherever a scenario-created record's `name`
# is echoed in a response. The 8-hex run_id changes every run and is pure
# diff churn -- strip it so only the stable `live-<run>-<slug>` shape persists.
_LIVE_RUN_RE = re.compile(r"\blive-[0-9a-f]{8}-", re.I)
# Any private-range IPv4 (other lab boxes show up in configs, agent records and
# request headers, not just the base host) and the per-run mirror API key name.
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
_MIRROR_KEY_RE = re.compile(r"\bauthprobe-mirror-[0-9a-f]{8}\b")

# Server-side timestamps that vary record-by-record and run-by-run. Normalized
# to a fixed epoch in `_scrub` so observation files diff only when shape /
# content changes, not when the appliance has had time pass since the last
# capture. Placeholder is 2023-11-14T22:13:20Z -- recognisably epoch-seconds,
# stable forever. The per-observation `captured_at` field carries the real
# date the op was validated; that one is intentionally preserved.
_TIMESTAMP_PLACEHOLDER = 1700000000
_TIMESTAMP_KEYS = frozenset((
    "createDate", "modifyDate", "lastReplyDate",
    "respDueDate", "dueBy", "uploadDate", "expiryDate",
    "lastModified", "lastTriggered",
))

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
        v = _LIVE_RUN_RE.sub("live-<run>-", v)
        v = _PRIVATE_IP_RE.sub("<lab-host>", v)
        v = _MIRROR_KEY_RE.sub("authprobe-mirror-<run>", v)
        return v
    if isinstance(value, dict):
        return {k: (_TIMESTAMP_PLACEHOLDER
                    if k in _TIMESTAMP_KEYS and isinstance(v, (int, float))
                    else _scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value

# Dict keys whose VALUES are runtime-polymorphic -- their inner shape depends on
# which playbook step ran, which audit row was returned, etc. Treated as shape-
# equal whenever both sides are dicts (or both are not), so the freeze logic
# doesn't refresh the whole captured body every time the appliance happens to
# have a different "latest" record at the top of the list.
_OPAQUE_DICT_KEYS = frozenset((
    "result",       # workflow step output / response builder payload
    "env",          # workflow step-local environment bag
    "data",         # audit-activities row payload + various wrappers
    "metadata",     # workflow metadata blob (graph + per-step data)
    "config",       # connector configuration field map
    "globalVariables",  # picklist + global vars referenced by a workflow
    "args",         # workflow step input args (varies per step type)
    "input",        # workflow step input payload (per step type)
    "output",       # workflow step output payload (per step type)
    "params",       # operation params (varies per connector op)
    "mock_result",  # mock step output (free-form)
    "request",      # workflow trigger request envelope (free-form)
))


def _same_shape(a: Any, b: Any, parent_key: str = "") -> bool:
    """Structural equality check used by the freeze-on-shape-match merge.

    Two values have the same shape when:
      - They are the same primitive type (int and float treated as numeric).
      - Dicts have identical key sets and each value has the same shape.
      - Lists have shape-matching elements; element order is ignored -- we
        compare the *set* of element shapes so a list rotating its members
        (audit log, workflow runs) does not register as a shape change. A
        list whose elements differ in shape *between* prior and current is
        treated as changed (new field on one of the records).

    Primitive values are NOT compared -- only their types -- so a `"name"`
    that changed from `"Foo"` to `"Bar"` keeps the same shape. This is what
    lets us freeze examples whose content drifts but whose schema is
    stable, while still surfacing genuinely new fields.
    """
    # Polymorphic-by-design buckets: shape-equal regardless of inner contents.
    # These keys carry free-form payloads whose schema is the calling
    # connector / playbook step's contract, not the FortiSOAR API's. Treat
    # any pair (dict, list, str, null, ...) as equivalent so swapping the
    # underlying step type doesn't churn the captured example.
    if parent_key in _OPAQUE_DICT_KEYS:
        return True
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            return False
        return all(_same_shape(a[k], b[k], parent_key=k) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        if not a and not b:
            return True
        if not a or not b:
            # one empty, one not -- shape ambiguous; treat as same if either
            # side has a homogeneous shape we can confirm against. Empty
            # list -> assume same as non-empty's element shape.
            return True
        # Heterogeneous lists (e.g. audit-activities returns different audit
        # event types interleaved) get a union-based shape check: collapse
        # every dict element on each side into "the union of all keys seen,
        # mapped to one representative value", then compare those merged
        # shapes. This lets the captured mix vary without registering as a
        # schema change, while still catching a genuinely new field type.
        def _merge(lst):
            if all(isinstance(x, dict) for x in lst):
                merged: dict = {}
                for elt in lst:
                    for k, v in elt.items():
                        if k not in merged or merged[k] is None:
                            merged[k] = v
                return [merged]
            return lst
        ma = _merge(a)
        mb = _merge(b)
        if len(ma) != len(mb):
            return False
        return all(_same_shape(x, y, parent_key=parent_key) for x, y in zip(ma, mb))
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return True
    # `None` on one side and a primitive on the other is the common "nullable
    # field" pattern (parent_wf_id is null for root workflows, int for child
    # runs; closureNotes null until set). Treat as shape-compatible -- a real
    # schema change shows up as a type *flip* between two non-None types, or
    # as a key set difference one level up.
    if a is None or b is None:
        return True
    return type(a) is type(b)


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
    # (method, url, status, location) for any response that was a 3xx before
    # we followed it. Surfaced at the end of the run so we can flag routes
    # whose curl examples need `-L`.
    redirects: list[tuple[str, str, int, str]] = field(default_factory=list)

    def set_auth(self, mode: str) -> None:
        if mode not in self.auth_modes:
            raise KeyError(f"unknown auth mode {mode!r}; have {list(self.auth_modes)}")
        self.headers["Authorization"] = self.auth_modes[mode]
        self.current_auth = mode

    def request(self, method: str, path: str, **kw) -> requests.Response:
        url = f"{self.base}{path}"
        kw.setdefault("allow_redirects", False)
        # Allow callers to override the default per-request timeout without
        # colliding with the explicit `timeout=self.timeout` below (which would
        # otherwise raise "got multiple values for keyword argument 'timeout'").
        timeout = kw.pop("timeout", self.timeout)
        # Per-call header overrides (e.g. the MCP JSON-RPC routes demand
        # `Accept: application/json, text/event-stream`) merge over the
        # session defaults instead of replacing them.
        hdrs = {**self.headers, **kw.pop("headers", {})}
        r = requests.request(method, url, headers=hdrs, verify=self.verify,
                             timeout=timeout, **kw)
        if 300 <= r.status_code < 400 and r.headers.get("Location"):
            self.redirects.append((method.upper(), url, r.status_code, r.headers["Location"]))
            kw["allow_redirects"] = True
            r = requests.request(method, url, headers=self.headers, verify=self.verify,
                                 timeout=timeout, **kw)
        return r

    def call(
        self,
        method: str,
        template: str,
        want: int | tuple[int, ...] | None = None,
        path_params: dict[str, str] | None = None,
        files: dict | None = None,
        capture_body: bool = True,
        sse: bool = False,
        **kw,
    ) -> tuple[requests.Response, dict | list | None]:
        """Make a request against a path *template* and record the observation.

        `template` is the OpenAPI path (e.g. `/api/integration/configuration/{config_id}/`).
        `path_params` are substituted into it to form the concrete URL. The pair
        `(method, template)` becomes the key under which the request/response are
        stored for `build_curated.py` to consume.

        When `files` is given, the request is sent as `multipart/form-data` --
        `Content-Type` is omitted from headers so requests picks the right
        boundary. The captured "request body" then summarizes the multipart
        parts rather than echoing the raw binary.

        With `sse=True` the response is expected as server-sent events (the
        MCP JSON-RPC routes): the recorded body becomes the JSON carried in
        the `data:` frames instead of `null` (SSE text is not JSON). Extra
        `headers` in `**kw` merge over the session defaults (e.g. the MCP
        routes demand `Accept: application/json, text/event-stream`).
        """
        path = template.format(**(path_params or {}))
        if files is not None:
            # Strip Content-Type so requests sets multipart/form-data with the
            # right boundary. Don't mutate self.headers -- copy.
            hdrs = {k: v for k, v in self.headers.items() if k.lower() != "content-type"}
            timeout = kw.pop("timeout", self.timeout)
            url = f"{self.base}{path}"
            kw.setdefault("allow_redirects", False)
            r = requests.request(method, url, headers=hdrs, verify=self.verify,
                                 timeout=timeout, files=files, **kw)
            if 300 <= r.status_code < 400 and r.headers.get("Location"):
                self.redirects.append((method.upper(), url, r.status_code, r.headers["Location"]))
                kw["allow_redirects"] = True
                r = requests.request(method, url, headers=hdrs, verify=self.verify,
                                     timeout=timeout, files=files, **kw)
            captured_req: Any = {f: "<binary>" for f in files}
        else:
            r = self.request(method, path, **kw)
            captured_req = _scrub(kw.get("json"))
        try:
            resp_body = r.json() if r.content else None
        except ValueError:
            resp_body = None
        if sse and resp_body is None and r.text:
            # MCP JSON-RPC routes answer as server-sent events
            # (`event: message\ndata: {...}`). Record the JSON-RPC payload
            # carried in the `data:` frames, not the SSE framing itself --
            # that is what a client hands to its JSON-RPC layer.
            chunks = [ln[5:].strip() for ln in r.text.splitlines() if ln.startswith("data:")]
            if chunks:
                try:
                    resp_body = json.loads("".join(chunks))
                except ValueError:
                    resp_body = None
        # Record BEFORE assertion so failure cases (e.g. apikey 403 on an
        # admin endpoint) still surface in the per-auth coverage report.
        # capture_body=False records the status but no bodies -- for binary
        # responses (installer .bin) whose megabytes must not land in the
        # examples store. The op still counts as live-captured (2xx).
        key = f"{method.upper()} {template}"
        per_op = self.observations.setdefault(key, {"by_auth": {}})
        per_op["by_auth"][self.current_auth] = {
            "request_body": captured_req if capture_body else None,
            "response_status": r.status_code,
            "response_body": (_scrub(resp_body) if r.status_code < 400 else None)
            if capture_body else None,
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


def open_session(api_key: str = "") -> Session:
    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    if not base:
        sys.exit("FSR_BASE_URL missing from .env")
    verify = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
    timeout = int(os.environ.get("FSR_TEST_TIMEOUT", "20"))

    api_key = api_key or os.environ.get("FSR_API_KEY", "")
    user = os.environ.get("FSR_USERNAME", "")
    pw = os.environ.get("FSR_PASSWORD", "")

    # Try to acquire BOTH auth modes -- every scenario then runs once per mode
    # so either mode can supply a live example. Which credentials an op accepts
    # is measured by src/auth_probe.py, not inferred from these runs.
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
    try:
        removed += _sweep_api_key_scopes(s)
        removed += _sweep_api_key_users(s)
    except AssertionError:
        pass  # API-key auth not available on this box
    removed += _sweep_connector_configs(s)
    removed += _sweep_hello_world_connectors(s)
    removed += _sweep_query_objects(s)
    removed += _sweep_alerts(s)
    removed += _sweep_named(s, "/api/3/incidents", "incident")
    removed += _sweep_named(s, "/api/3/tasks", "task")
    removed += _sweep_live_comments(s)
    removed += _sweep_named(s, "/api/3/roles", "role")
    removed += _sweep_named(s, "/api/3/teams", "team")
    removed += _sweep_named(s, "/api/3/agents", "agent")
    removed += _sweep_picklists(s)
    removed += _sweep_mcp_configs(s)
    removed += _sweep_scheduled(s)
    removed += _sweep_indicators(s)
    removed += _sweep_live_playbooks(s)
    removed += _sweep_staging_metadata(s)
    return removed


def _sweep_staging_metadata(s: Session) -> int:
    """DELETE staging_model_metadatas rows whose type carries the live marker.

    A crash between the staging lifecycle's create and delete would otherwise
    leave a staged schema row behind -- and the NEXT ``PUT /api/publish``
    (misc_reads, captured only when the staging table is empty) would flush
    it into the live schema.
    """
    removed = 0
    r = s.request("GET", "/api/3/staging_model_metadatas?$limit=200")
    if not r.ok:
        return 0
    try:
        members = extract_members(r.json())
    except ValueError:
        return 0
    for m in members:
        mtype = str(m.get("type") or "")
        if not (mtype.startswith(LIVE_PREFIX) or mtype.startswith("live")):
            continue
        uuid = m.get("uuid") or (m.get("@id") or "").rsplit("/", 1)[-1]
        if uuid:
            s.request("DELETE", f"/api/3/staging_model_metadatas/{uuid}")
            removed += 1
    return removed


def _sweep_live_comments(s: Session) -> int:
    """DELETE comments whose content carries the LIVE_PREFIX marker."""
    removed = 0
    r = s.request("GET", "/api/3/comments?$limit=200&$search=" + LIVE_PREFIX)
    if not r.ok:
        return 0
    try:
        members = extract_members(r.json())
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
        members = extract_members(r.json())
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
        members = extract_members(r.json())
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
        members = extract_members(r.json())
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
        members = extract_members(r.json())
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

    No record creation -- every call is either a GET or a side-effect-free POST.
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
            members = extract_members(r.json())
        except ValueError:
            members = []
        if members:
            uuid_ = members[0].get("uuid") or (members[0].get("@id", "").rsplit("/", 1)[-1])
            if uuid_:
                s.call("GET", "/api/3/{collection}/{uuid}", want=200,
                       path_params={"collection": "alerts", "uuid": uuid_})


@scenario("ai")
def scenario_ai(s: Session) -> None:
    """Exercise the 8.0+ AI / FortiAI surface with REAL lifecycles (own records only).

    FortiAI answers through the ``fortinet-fortiai-proxy`` connector (LLM
    profiles with ``provider: "fortisoar"``). Every LLM-backed call below uses
    a deliberately tiny query so the appliance's FortiAI token spend stays
    minimal. Own-things contract: the scheduled insight created here is deleted
    again (the AI DELETE also removes the underlying ``/api/3/insights`` record
    -- a follow-up api3 DELETE 404s); agent runs are stateless (ioc-masking on
    a literal string); nothing that ships with the appliance (agents, LLM
    profiles, MCP configurations) is modified.

    Live-verified shapes on 8.0.0:
      - ``chat`` takes ``messages`` as plain STRINGS (role-tagged objects 422);
        the answer carries ``thread_id`` / ``intent`` / ``message_history``.
      - ``insight/chain_of_thoughts`` returns ``{"chain_of_thought": [..]}``;
        ``insight/plan`` wants that LIST as ``chain_of_thought``; ``plan``
        alone omits it, so ``plan/execute`` needs it stitched back in
        (``plan: {**plan, "chain_of_thought": steps}``).
      - ``insight/plan/execute`` -> ``{status: "accepted", planid, task_id}``;
        status polls ``{"status": "inprogress"}`` and result returns
        ``{result, execution_log, last_executed}`` (empty while running).
      - ``insight/trigger/schedule`` wants ``{referenceid, createUser}`` over a
        SAVED insight (``POST /api/3/insights``); ``createUser`` is the
        owner's ``/api/3/people`` IRI.
      - agent trigger/status/result answer **202** for the whole task life
        (not 200); the trigger body is
        ``{input_data: {<agent inputformat fields>}, context: {}, user_id}``.
      - ``llm/config`` POST takes a LIST of profiles; the DELETE route 400s
        with a TypeError for every profile on 8.0.0 (FortiAI bug), so no
        profile is created here -- it could not be cleaned up.
      - ``llm/config/{uuid}/verify`` wants ``?model_id=`` (the config uuid per
        the fsr-ai handler); only OpenAI-style profiles implement verify --
        ``fortisoar`` profiles raise NotImplementedError (500).
      - the traces family (list/health/tokens/spans) 403s with
        ``AccessDeniedException`` behind the tracer store on this appliance --
        environment-limited, not a route problem.
      - ``enrich/context`` + ``enrich/context/index`` 500 (the organizational
        context KB is not configured here); the index body is the
        OrganizationalContextDTO (``title``/``content``/``type_``/...).
      - ``agent/config`` POST 404s (``'NoneType' object has no attribute
        'id'``) and the per-agent GET 500s on 8.0.0.
      - the ``/mcp/*`` gateway routes speak JSON-RPC 2.0 over streamable HTTP
        and need ``Accept: application/json, text/event-stream`` -- anything
        else 406s. Captures here run ``tools/list`` (after an unrecorded
        ``initialize`` handshake, which must come first per protocol).
    """
    _ok = (200, 401, 403)
    _post = (200, 201, 202, 204, 400, 404, 422, 500, 401, 403)
    _sse = {"Accept": "application/json, text/event-stream"}

    print("[ai] agent list + LLM config + MCP server list")
    _, agent_list = s.call("GET", "/api/ai/agent/", want=_ok)
    _, llm_list = s.call("GET", "/api/ai/llm/config", want=_ok)
    s.call("GET", "/api/ai/mcp", want=(200, 201, 401, 403))

    print("[ai] MCP CRUD store + connector candidates + activity")
    s.call("GET", "/api/3/mcp_configurations", want=_ok)
    s.call("GET", "/mcp/servers/connector", want=_ok, params={"restricted": "true"})
    s.call("GET", "/api/3/llm_activity_logs", want=_ok)

    print("[ai] insight list + default agent config")
    s.call("GET", "/api/ai/insight/", want=_ok)
    s.call("GET", "/api/ai/agent/config/default", want=_ok)

    print("[ai] traces family (tracer store 403s on this box -- recorded as-is)")
    s.call("GET", "/api/ai/traces/health", want=(200, 401, 403))
    s.call("GET", "/api/ai/traces/", want=(200, 401, 403))

    print("[ai] agent detail (by name/version + by uuid)")
    agents = agent_list if isinstance(agent_list, list) else []
    if agents:
        a = next((x for x in agents if x.get("name") == "ioc-masking"), agents[0])
        a_name, a_ver, a_uuid = a.get("name"), a.get("version"), a.get("uuid")
        if a_name and a_ver:
            s.call("GET", "/api/ai/agent/{name}/{version}", want=_ok,
                   path_params={"name": a_name, "version": a_ver})
            s.call("GET", "/api/ai/agent/{name}/{version}/relationships", want=_ok,
                   path_params={"name": a_name, "version": a_ver})
            s.call("GET", "/api/ai/agent/config/{agent_name}/{version}", want=(200, 404, 500, 401, 403),
                   path_params={"agent_name": a_name, "version": a_ver})
        if a_uuid:
            s.call("GET", "/api/ai/agent/{uuid}", want=_ok,
                   path_params={"uuid": a_uuid})

    print("[ai] LLM config detail + verify (fortisoar provider verify 500s by design)")
    llms = llm_list if isinstance(llm_list, list) else []
    default_llm = next((p for p in llms if isinstance(p, dict) and p.get("isdefault")), None)
    if default_llm and default_llm.get("uuid"):
        s.call("GET", "/api/ai/llm/config/{uuid}", want=_ok,
               path_params={"uuid": default_llm["uuid"]})
        s.call("GET", "/api/ai/llm/config/{uuid}/verify", want=(200, 422, 500, 401, 403),
               path_params={"uuid": default_llm["uuid"]},
               params={"model_id": default_llm["uuid"]})

    print("[ai] chat (messages are plain strings)")
    _, chat = s.call("POST", "/api/ai/chat/", want=(200, 401, 403, 422, 500),
                     json={"user_id": s.live_name("ai"), "messages": ["Reply with exactly: pong"]})

    print("[ai] chain_of_thoughts -> plan -> execute -> status/result")
    socrole = "SOC Analyst"
    tiny_query = "Reply with the single word: pong"
    _, cot = s.call("POST", "/api/ai/insight/chain_of_thoughts", want=(200, 401, 403, 422, 500),
                    json={"socrole": socrole, "query": tiny_query})
    steps = (cot or {}).get("chain_of_thought") or [] if isinstance(cot, dict) else []
    _, plan = s.call("POST", "/api/ai/insight/plan", want=(200, 401, 403, 422, 500),
                     json={"socrole": socrole, "query": tiny_query, "chain_of_thought": steps})
    plan_body = dict(plan) if isinstance(plan, dict) else {}
    plan_body["chain_of_thought"] = steps
    _, executed = s.call("POST", "/api/ai/insight/plan/execute", want=(200, 401, 403, 422, 500),
                         json={"socrole": socrole, "plan": plan_body})
    ex_task = (executed or {}).get("task_id") if isinstance(executed, dict) else None
    if ex_task:
        s.call("GET", "/api/ai/insight/plan/{task_id}/status", want=(200, 404, 422, 401, 403),
               path_params={"task_id": ex_task})
        s.call("GET", "/api/ai/insight/plan/{task_id}/result", want=(200, 404, 422, 401, 403),
               path_params={"task_id": ex_task})

    print("[ai] scheduled insight lifecycle (own record, deleted again)")
    if ex_task and (executed or {}).get("planid"):
        _, saved = s.call("POST", "/api/3/insights", want=(200, 201, 400, 422, 401, 403),
                          json={"title": s.live_name("insight"), "query": tiny_query,
                                "socrole": socrole, "planid": executed["planid"]})
        ins_uuid = (saved or {}).get("uuid") if isinstance(saved, dict) else None
        if ins_uuid:
            owner = s.request("GET", f"/api/3/insights/{ins_uuid}").json()
            owner_ref = (owner or {}).get("createUser")
            owner_iri = owner_ref.get("@id") if isinstance(owner_ref, dict) else owner_ref
            s.call("POST", "/api/ai/insight/trigger/schedule", want=(200, 401, 403, 422, 500),
                   json={"referenceid": ins_uuid, "createUser": owner_iri})
            s.call("GET", "/api/ai/insight/{insight_id}", want=(200, 404, 500, 401, 403),
                   path_params={"insight_id": ins_uuid})
            s.call("DELETE", "/api/ai/insight/{insight_id}", want=(200, 204, 404, 401, 403),
                   path_params={"insight_id": ins_uuid})
            # the AI delete cascades: the api3 record is gone too (404, not deleted twice)
            s.request("DELETE", f"/api/3/insights/{ins_uuid}")

    print("[ai] agent run lifecycle: trigger -> status -> result (all 202)")
    if agents:
        a = next((x for x in agents if x.get("name") == "ioc-masking"), agents[0])
        a_name, a_ver = a.get("name"), a.get("version")
        if a_name:
            _, trig = s.call("POST", "/api/ai/agents/{agent_name}/trigger", want=(200, 202, 401, 403, 422, 500),
                             path_params={"agent_name": a_name},
                             json={"input_data": {"data": "Contact alice@example.com about incident 12345",
                                                  "action": "mask"},
                                   "context": {}, "user_id": s.live_name("ai")})
            task_id = (trig or {}).get("task_id") if isinstance(trig, dict) else None
            if task_id:
                for _ in range(24):
                    time.sleep(5)
                    _, st = s.call("GET", "/api/ai/agents/{task_id}/status", want=(200, 202, 404, 401, 403),
                                   path_params={"task_id": task_id})
                    if isinstance(st, dict) and st.get("status") in ("completed", "failed", "error"):
                        break
                s.call("GET", "/api/ai/agents/{task_id}/result", want=(200, 202, 404, 401, 403),
                       path_params={"task_id": task_id})
                # analyst feedback: crashes 400 TypeError for EVERY body on
                # 8.0.0 (FortiAI bug) -- recorded for the status, prose notes it
                s.call("POST", "/api/ai/agents/{task_id}/acceptance", want=(200, 202, 400, 404, 401, 403),
                       path_params={"task_id": task_id}, json={"accepted": True})

    print("[ai] MCP validate against the appliance's own module server")
    _, mcps = s.call("GET", "/api/3/mcp_configurations", want=_ok)
    mcp_rows = extract_members(mcps) if isinstance(mcps, (dict, list)) else []
    target = next((m for m in mcp_rows if isinstance(m, dict) and m.get("transport") == "http"
                   and str(m.get("url", "")).startswith("https://localhost/")), None)
    if target:
        s.call("POST", "/api/ai/mcp/validate", want=(200, 401, 403, 422, 500),
               json={"uuid": target.get("uuid"), "name": target.get("name"),
                     "transport": target.get("transport"), "url": target.get("url"),
                     "authentication": {"type": "FSR"}})

    print("[ai] MCP gateway JSON-RPC (initialize handshake, then tools/list capture)")
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "live-test", "version": "0.0.1"}}}
    for template, path_params in (
            ("/mcp/modules/", {}),
            ("/mcp/playbooks/", {}),
            ("/mcp/utility/", {}),
            ("/mcp/connector/{connector_name}/", {"connector_name": "aws"}),
    ):
        path = template.format(**path_params)
        r = s.request("POST", path, json=init, headers=_sse, timeout=60)
        sid = r.headers.get("Mcp-Session-Id") or r.headers.get("mcp-session-id")
        if r.ok and sid:
            # tools/list under the initialize-issued session; the SSE-framed
            # answer is recorded as the JSON-RPC payload (sse=True)
            s.call("POST", template, want=(200, 401, 403, 404, 406), sse=True,
                   path_params=path_params or None,
                   headers={**_sse, "Mcp-Session-Id": sid},
                   json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        else:
            print(f"  [ai] {path}: initialize -> {r.status_code}; skipping tools/list capture")

    print("[ai] agent config write + export/import (error shapes recorded)")
    s.call("POST", "/api/ai/agent/config", want=_post, json={})
    s.call("POST", "/api/ai/agent/config/default", want=_post, json={})
    if agents:
        a_id = agents[0].get("id") or agents[0].get("uuid")
        if a_id:
            s.call("POST", "/api/ai/agent/export/{agent_id}", want=_post,
                   path_params={"agent_id": str(a_id)}, json={})
    s.call("POST", "/ai/agent/import", want=_post, json={})

    print("[ai] enrich (context KB not configured on this box -- 500s recorded)")
    s.call("POST", "/api/ai/enrich/context", want=_post,
           json={"query": tiny_query})
    s.call("POST", "/api/ai/enrich/context/index", want=_post,
           json={"uuid": None, "title": s.live_name("doc"), "category": "runbook",
                 "subCategory": None, "description": "live-test document",
                 "content": "live-test content", "llmSummarize": False,
                 "type_": "organizational_context"})
    s.call("POST", "/api/ai/enrich/index/build", want=_post, json={})


@scenario("misc_reads")
def scenario_misc_reads(s: Session) -> None:
    """Read-only sweeps of uncovered non-AI endpoints.

    Comments, scheduled tasks, staging/model metadata, MCP servers,
    publish state, auth config write-back, export/import template stubs.
    Run-control (start/resume/approval) lives in wf_triggers_lifecycle;
    AI/MCP bodies live in the ai scenario and the MCP hosting probe.
    """
    _ok = (200, 401, 403)
    _post = (200, 201, 202, 204, 400, 402, 404, 405, 406, 422, 500, 502, 401, 403)

    print("[misc] comments list")
    s.call("GET", "/api/3/comments", want=_ok, params={"$limit": 1})

    print("[misc] scheduled tasks list + trigger-now")
    _, sched_list = s.call("GET", "/api/wf/api/scheduled/", want=(200, 502, 401, 403), params={"limit": 1})
    sched_items = []
    if isinstance(sched_list, dict):
        sched_items = sched_list.get("hydra:member") or sched_list.get("results") or []
    if sched_items:
        sched_id = sched_items[0].get("id")
        if sched_id:
            s.call("POST", "/api/wf/api/scheduled/trigger-now/", want=_post,
                   json={"id": sched_id})
    else:
        s.call("POST", "/api/wf/api/scheduled/trigger-now/", want=_post, json={})
    # POST /api/wf/api/scheduled/ is exercised with a real (disabled) task by
    # api3_lifecycles; an empty-body probe here would overwrite that capture.

    print("[misc] staging + model metadata detail")
    r = s.request("GET", "/api/3/staging_model_metadatas?$limit=1")
    if r.ok:
        members = extract_members(r.json())
        if members:
            stag_uuid = members[0].get("uuid") or members[0].get("@id", "").rsplit("/", 1)[-1]
            if stag_uuid:
                s.call("GET", "/api/3/staging_model_metadatas", want=_ok, params={"$limit": 1})
                s.call("GET", "/api/3/staging_model_metadatas/{uuid}", want=_ok,
                       path_params={"uuid": stag_uuid})
    r2 = s.request("GET", "/api/3/model_metadatas?$limit=1")
    if r2.ok:
        members2 = extract_members(r2.json())
        if members2:
            mm_uuid = members2[0].get("uuid") or members2[0].get("@id", "").rsplit("/", 1)[-1]
            if mm_uuid:
                s.call("GET", "/api/3/model_metadatas/{uuid}", want=_ok,
                       path_params={"uuid": mm_uuid})

    print("[misc] publish state + MCP servers by type")
    s.call("GET", "/api/publish/error", want=_ok)
    # Appliance-wide publish. Guarded: it flushes EVERY staged schema change,
    # so it only runs when the staging table is empty (the staging lifecycle
    # below creates and deletes its own row; the pre-sweep removes crash
    # leftovers). Empty staging -> the publish is a no-op run that still
    # yields the real shape: 200 {"status": "started"}.
    r_pub = s.request("GET", "/api/3/staging_model_metadatas?$limit=100")
    staged = extract_members(r_pub.json()) if r_pub.ok else []
    if staged:
        print(f"  [misc] staging table not empty ({len(staged)} row(s)); skipping PUT /api/publish")
    else:
        s.call("PUT", "/api/publish", want=(200, 400, 401, 403), json={})
    for mcp_type in ("connector", "utility", "playbook", "module"):
        s.call("GET", "/mcp/servers/{mcp_type}", want=_ok,
               path_params={"mcp_type": mcp_type},
               params={"restricted": "true"})

    print("[misc] MCP gateway routes are captured by the ai scenario (JSON-RPC + SSE)")

    print("[misc] auth license POST + logout probe")
    s.call("POST", "/api/auth/license", want=(200, 400, 401, 403), json={})

    # NOTE: workflow run-control (start/resume/approval) is owned by
    # wf_triggers_lifecycle against OUR clone's runs -- stub calls here would
    # both overwrite those captures with empty-body shapes and fire arbitrary
    # playbooks. wfinput_resume / retry / notrigger / triggers-1-{name} are
    # owned by wf_triggers_lifecycle too (real 2xx lifecycles); stub calls here
    # would overwrite those captures with 4xx shapes.
    s.call("POST", "/api/wf/api/manual-wf-input/{pk}/retrieve_wfinput/", want=_post,
           path_params={"pk": "1"}, json={})

    print("[misc] triggers + notifications")
    s.call("POST", "/api/triggers/1/deferred/{name}", want=_post,
           path_params={"name": "nonexistent"}, json={})
    s.call("POST", "/api/rule/api/system-notification/notifications/", want=_post, json={})
    s.call("POST", "/api/rule/api/system-notification/purge/", want=_post, json={})

    print("[misc] widget export + development read")
    r4 = s.request("GET", "/api/3/widgets?$limit=1")
    if r4.ok:
        w_members = extract_members(r4.json())
        if w_members:
            w_uuid = w_members[0].get("uuid") or w_members[0].get("@id", "").rsplit("/", 1)[-1]
            if w_uuid:
                s.call("GET", "/api/3/widgets/development/{uuid}", want=_ok,
                       path_params={"uuid": w_uuid})
                s.call("POST", "/api/3/widgets/export/{uuid}", want=_post,
                       path_params={"uuid": w_uuid}, json={})

    print("[misc] feeds + bulk reads; write-side lifecycles live in api3_lifecycles")
    s.call("POST", "/api/insert-feeds/{recordType}", want=_post,
           path_params={"recordType": "indicator"}, json={})
    print("[misc] staging metadata lifecycle (own record, deleted again)")
    r4 = s.request("GET", "/api/3/staging_model_metadatas", params={"$limit": 1})
    sample4 = next(iter(extract_members(r4.json()) if r4.ok else []), None)
    if sample4:
        body4 = {k: sample4[k] for k in ("parentType", "ownable", "userOwnable", "queueable",
                                         "trackable", "taggable", "peerReplicable", "defaultSort",
                                         "uniqueConstraint", "indexable")
                 if k in sample4 and sample4[k] is not None}
        body4.update(type=f"live{s.run_id}module", tableName=f"live{s.run_id}_module")
        _, staged = s.call("POST", "/api/3/staging_model_metadatas", want=(201, 400, 401, 403),
                           json=body4)
        if isinstance(staged, dict) and staged.get("@id"):
            s.call("DELETE", "/api/3/staging_model_metadatas/{uuid}", want=(204, 401, 403, 404),
                   path_params={"uuid": staged["@id"].rsplit("/", 1)[-1]})
    else:
        s.call("POST", "/api/3/staging_model_metadatas", want=_post, json={})
    # NOTE: /mcp/config/export + /api/ai/llm/config POST + the AI insight
    # detail are captured with REAL bodies by the ai scenario / the MCP
    # hosting probe; empty-body stubs here would clobber those captures.
    print("[misc] MCP config detail + agent heartbeat + PUT stubs")
    r5 = s.request("GET", "/api/3/mcp_configurations?$limit=1")
    if r5.ok:
        mc_members = extract_members(r5.json())
        if mc_members:
            mc_uuid = mc_members[0].get("uuid") or mc_members[0].get("@id", "").rsplit("/", 1)[-1]
            if mc_uuid:
                s.call("GET", "/api/3/mcp_configurations/{uuid}", want=_ok,
                       path_params={"uuid": mc_uuid})
    # Heartbeat against a REAL agent's `agentId` (the 32-hex bus identity —
    # the record uuid 500s on 8.0.0). Falls back to the uuid shape only when
    # the appliance has no agent records, keeping that failure documented.
    r7 = s.request("GET", "/api/3/agents", params={"$limit": 1})
    agent = next((a for a in extract_members(r7.json()) if r7.ok), None)
    agent_key = (agent or {}).get("agentId") or (agent or {}).get("uuid") or "nonexistent"
    s.call("GET", "/api/integration/agent-heartbeat/{agent}/", want=(200, 404, 500, 401, 403),
           path_params={"agent": str(agent_key)})
    # auth/config write-back: flip the retrievable_mode boolean and put it
    # back, so the 2xx capture is deterministic (writing the CURRENT value
    # 500s with "already set to [..]" on 8.0.0). Final state == initial.
    r6 = s.request("GET", "/api/auth/config", params={"section": "API-KEYS"})
    opt = next((m for m in extract_members(r6.json()) if r6.ok
                and m.get("key") == "retrievable_mode"), None)
    if opt is not None:
        orig = bool(opt.get("value"))
        s.call("PUT", "/api/auth/config", want=(200, 400, 401, 403),
               json={"option": "retrievable_mode", "value": not orig})
        s.call("PUT", "/api/auth/config", want=(200, 400, 401, 403),
               json={"option": "retrievable_mode", "value": orig})
    else:
        s.call("PUT", "/api/auth/config", want=(200, 400, 405, 500, 401, 403), json={})
    s.call("PUT", "/api/publish/revert", want=(200, 400, 405, 401, 403), json={})

    print("[misc] export/import templates + jobs (live-* names)")
    s.call("POST", "/api/3/export_templates", want=(200, 201, 400, 422, 401, 403),
           json={"name": f"{LIVE_PREFIX}export-template"})
    s.call("POST", "/api/3/export_jobs", want=(200, 201, 400, 422, 401, 403),
           json={"name": f"{LIVE_PREFIX}export-job"})
    s.call("POST", "/api/3/import_jobs", want=(200, 201, 400, 422, 401, 403),
           json={"name": f"{LIVE_PREFIX}import-job"})
    s.call("POST", "/api/3/picklist_names", want=(200, 201, 400, 409, 422, 401, 403),
           json={"name": f"{LIVE_PREFIX}picklist-name", "description": "live test"})


@scenario("queries")
def scenario_queries(s: Session) -> None:
    """Exercise the Query API end-to-end.

    Steps:
      1. POST /api/query/alerts          -> ad-hoc query (read-only).
      2. POST /api/3/query_objects       -> persist a saved query (live-* name).
      3. POST /api/query/alerts/{id}/indicators -> the indicators linked to one alert.
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
        m = extract_members(r.json())
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

    print("[queries] step 3: indicators linked to one alert")
    r = s.request("GET", "/api/3/alerts?$limit=1")
    alerts = extract_members(r.json()) if r.ok else []
    if alerts:
        s.call("POST", "/api/query/{collection}/{id}/{field}", want=200,
               path_params={"collection": "alerts", "id": alerts[0]["uuid"], "field": "indicators"},
               params={"$limit": 2}, json={"logic": "AND", "filters": []})

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
    # collections -- Django REST style, distinct from the Hydra `limit` used
    # under `/api/3/`. Capping to 1 keeps the captured example readable.
    s.call("GET", "/api/integration/configuration/", want=200, params={"page_size": 1})

    print("[connector] step 3: create configuration")
    # `agent` is intentionally omitted -- it's only required when delegating
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
        for m in (extract_members(r.json())):
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
        for m in (extract_members(r.json())):
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


@scenario("api3_lifecycles")
def scenario_api3_lifecycles(s: Session) -> None:
    """Write-side lifecycles: every create/update/delete touches ONLY records
    this run created (live- names), and each lifecycle ends with its own
    records deleted and verified gone.

    Payloads live-verified on 8.0.0-6034:
      - `POST/PUT /api/3/{insert,update}/{module}` want a `{"data": [...]}`
        wrapper (the bare-array shape the vendor guide shows TypeErrors).
      - `DELETE /api/3/delete/{module}` is broken on 8.0.0 (TypeError for
        every body shape, same as 7.6.x), so cleanup uses the per-record
        `DELETE /api/3/{module}/{uuid}` routes, which work.
      - `PUT /api/wf/api/scheduled/{id}/` needs the FULL record back plus
        `?format=json`; `{id}` is a per-request Fernet token from the
        create/list response, never a stored uuid.
    """
    _ok = (200, 201, 401, 403)
    _w = (200, 201, 202, 204, 400, 401, 403, 404, 405, 422, 500)

    # --- alerts: insert -> update -> related-query -> delete (own records) --
    sev = _picklist_iri(s, "Severity", "High")
    status = _picklist_iri(s, "AlertStatus", "Open")
    record_iri = None
    if sev and status:
        # Mirrored API keys hit "Invalid credentials" inside the bulk failure
        # array on this build (same as bulkupsert); capture it and move on.
        _, rows = s.call("POST", "/api/3/insert/{moduleType}", want=(201, 400, 401, 403, 500),
                         path_params={"moduleType": "alerts"},
                         json={"data": [{"name": s.live_name("insert"), "source": "live_test",
                                         "severity": sev, "status": status}]})
        created = (rows if isinstance(rows, list) else (rows or {}).get("hydra:member") or [])
        record_iri = next((r.get("@id") for r in created if isinstance(r, dict) and r.get("@id")), None)
        if not record_iri:
            r = s.request("GET", "/api/3/alerts", params={"$search": s.live_name("insert"), "$limit": 5})
            record_iri = next((m.get("@id") for m in extract_members(r.json()) if r.ok
                               and (m.get("name") or "").startswith(s.live_name("insert"))), None)
    else:
        print("[api3] picklist IRIs unresolved; skipping module-CRUD steps")

    if record_iri:
        s.call("PUT", "/api/3/update/{moduleType}", want=(200, 400, 401, 403),
               path_params={"moduleType": "alerts"},
               json={"data": [{"@id": record_iri, "description": f"updated by run {s.run_id}"}]})
        record_uuid = record_iri.rsplit("/", 1)[-1]
        r = s.request("GET", f"/api/3/alerts/{record_uuid}")
        if r.ok:
            print(f"[api3] update verified, description={((r.json() or {}).get('description'))!r}")
        # related-records query on our own alert before deleting it
        s.call("POST", "/api/query/{collection}/{id}/{field}", want=_ok,
               path_params={"collection": "alerts", "id": record_uuid, "field": "indicators"},
               json={"logic": "AND", "filters": []})
        # bulk delete is broken on 8.0.0; per-record delete of OUR record only
        if not s.request("DELETE", f"/api/3/alerts/{record_uuid}").ok:
            print(f"[api3] WARNING: cleanup delete failed for {record_iri}")
        else:
            print(f"[api3] record deleted ({r.status_code} after: "
                  f"{s.request('GET', f'/api/3/alerts/{record_uuid}').status_code})")

    # --- picklists: our own list + value, deleted before we leave ----------
    list_name = f"live{s.run_id}List"  # picklist names are unique instance-wide
    _, pln = s.call("POST", "/api/3/picklist_names", want=(201, 400, 401, 403, 409),
                    json={"name": list_name, "system": False})
    pln_iri = pln.get("@id") if isinstance(pln, dict) else None
    if pln_iri:
        _, val = s.call("POST", "/api/3/picklists", want=(201, 400, 401, 403),
                        json={"itemValue": s.live_name("opt"), "listName": pln_iri,
                              "color": "#4CAF50", "orderIndex": 1})
        val_iri = val.get("@id") if isinstance(val, dict) else None
        if val_iri:
            s.call("DELETE", "/api/3/picklists/{uuid}", want=(204, 401, 403, 404),
                   path_params={"uuid": val_iri.rsplit("/", 1)[-1]})
        s.call("DELETE", "/api/3/picklist_names/{uuid}", want=(204, 401, 403, 404),
               path_params={"uuid": pln_iri.rsplit("/", 1)[-1]})

    # --- MCP configurations: mirror an existing record's shape, then CRUD --
    r = s.request("GET", "/api/3/mcp_configurations", params={"$limit": 1})
    sample = next(iter(extract_members(r.json()) if r.ok else []), None)
    if sample:
        body = {k: sample[k] for k in ("active", "authentication", "command",
                                       "description", "metadata", "timeout",
                                       "transport", "type", "url")
                if k in sample and sample[k] is not None}
        body["name"] = s.live_name("mcp")
        _, cfg = s.call("POST", "/api/3/mcp_configurations", want=(201, 400, 401, 403),
                        json=body)
        cfg_iri = cfg.get("@id") if isinstance(cfg, dict) else None
        if cfg_iri:
            cfg_uuid = cfg_iri.rsplit("/", 1)[-1]
            _, fresh = s.call("GET", "/api/3/mcp_configurations/{uuid}", want=_ok,
                              path_params={"uuid": cfg_uuid})
            if isinstance(fresh, dict):
                s.call("PUT", "/api/3/mcp_configurations/{uuid}", want=(200, 400, 401, 403),
                       path_params={"uuid": cfg_uuid},
                       json={**fresh, "description": f"updated by run {s.run_id}"})
            s.call("DELETE", "/api/3/mcp_configurations/{uuid}", want=(204, 401, 403, 404),
                   path_params={"uuid": cfg_uuid})

    # --- scheduled tasks: disabled one-shot schedule on an existing workflow
    r = s.request("GET", "/api/3/workflows", params={"$limit": 1})
    wf = next(iter(extract_members(r.json()) if r.ok else []), None)
    if wf:
        wf_iri = wf.get("@id") or f"/api/3/workflows/{wf.get('uuid')}"
        _, task = s.call("POST", "/api/wf/api/scheduled/", want=(201, 400, 401, 403),
                         params={"format": "json"},
                         json={"name": s.live_name("schedule"),
                               "crontab": {"minute": "7", "hour": "3", "day_of_week": "*",
                                           "day_of_month": "1", "month_of_year": "1",
                                           "timezone": "UTC"},
                               "kwargs": {"exit_if_running": True, "wf_iri": wf_iri,
                                          "timezone": "UTC"},
                               "expires": None, "start_time": None,
                               "enabled": False})  # never actually fires
        if isinstance(task, dict) and task.get("id"):
            s.call("PUT", "/api/wf/api/scheduled/{id}/", want=(200, 400, 401, 403, 404),
                   path_params={"id": task["id"]}, params={"format": "json"},
                   json={**task, "enabled": False})
            s.call("DELETE", "/api/wf/api/scheduled/{id}/", want=(204, 401, 403, 404),
                   path_params={"id": task["id"]})

    # --- indicator feed ingest (trigger-bypassing), then delete our rows ---
    _, res = s.call("POST", "/api/ingest-feeds/indicators", want=(200, 400, 401, 403),
                    json={"data": [{"value": f"{s.live_name('ioc')}.example.invalid",
                                    "type": "all"}]})
    for uuid_ in (res or {}).get("uuids", []) if isinstance(res, dict) else []:
        if not s.request("DELETE", f"/api/3/indicators/{uuid_}").ok:
            print(f"[api3] WARNING: indicator cleanup failed for {uuid_}")

    # --- logout, on a throwaway token so our own session survives ----------
    user = os.environ.get("FSR_USERNAME", "")
    pw = os.environ.get("FSR_PASSWORD", "")
    if user and pw and s.current_auth == "jwt":
        import urllib.parse as _up
        r = s.request("POST", "/auth/authenticate",
                      json={"credentials": {"loginid": user, "password": pw}})
        if r.ok and r.json().get("token"):
            saved, s.headers["Authorization"] = s.headers["Authorization"], f"Bearer {r.json()['token']}"
            s.call("POST", "/api/3/logout", want=(200, 204, 401, 403))
            s.headers["Authorization"] = saved


def _awaiting_agent(s: Session) -> dict | None:
    """The agent record whose configurationHealth reads 'Awaiting Remote Node
    Connection' — install-connector against it queues without executing."""
    r = s.request("GET", "/api/3/agents", params={"$limit": 50})
    agents = extract_members(r.json()) if r.ok else []
    iris = {a.get("configurationHealth", {}).get("@id") for a in agents
            if isinstance(a.get("configurationHealth"), dict) and a["configurationHealth"].get("@id")}
    labels: dict[str, str] = {}
    if iris:
        rp = s.request("GET", "/api/3/picklists", params={"$limit": 1000})
        for p in extract_members(rp.json()) if rp.ok else []:
            if p.get("@id") in iris:
                labels[p["@id"]] = p.get("itemValue") or ""
    for a in agents:
        h = a.get("configurationHealth")
        iri = h.get("@id") if isinstance(h, dict) else h
        if labels.get(iri) == "Awaiting Remote Node Connection" and a.get("agentId"):
            return a
    return None


def _catalog_version(s: Session, name: str) -> str | None:
    r = s.request("GET", "/api/integration/connectors/",
                  params={"name": name, "format": "json"})
    data = (r.json() or {}).get("data") or [] if r.ok else []
    return (data[0] or {}).get("version") if data else None


def _sweep_live_playbooks(s: Session) -> int:
    """Delete live-* playbook clones and any manual inputs paused on their runs.

    The pending-input linkage goes input.workflow (numeric run id) -> run
    detail -> run name, so we only ever abandon inputs that belong to OUR
    cloned playbooks.
    """
    removed = 0
    r = s.request("GET", "/api/wf/api/manual-wf-input/", params={"format": "json", "limit": 100})
    rows = r.json() if r.ok else []
    rows = rows if isinstance(rows, list) else (rows or {}).get("hydra:member") or []
    for row in rows:
        run_pk = row.get("workflow")
        if not run_pk:
            continue
        det = s.request("GET", f"/api/wf/api/workflows/{run_pk}/", params={"format": "json"})
        name = (det.json() or {}).get("name") or "" if det.ok else ""
        if not name.startswith(LIVE_PREFIX):
            continue
        if s.request("DELETE", f"/api/wf/api/manual-wf-input/{row['id']}/",
                     params={"format": "json"}).ok:
            removed += 1
            print(f"  swept manual input {row['id']} (run {run_pk} of {name})")
    # the clones themselves ($search is the only working fuzzy filter on this
    # route; `name=` needs the exact full name and `name__startswith` is not
    # supported). Leftover clones are inert (their triggers do not self-fire);
    # the paused inputs above were the operational risk.
    r = s.request("GET", "/api/3/workflows", params={"$search": LIVE_PREFIX, "$limit": 100})
    for m in extract_members(r.json()) if r.ok else []:
        if not (m.get("name") or "").startswith(LIVE_PREFIX):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if uuid_ and s.request("DELETE", f"/api/3/workflows/{uuid_}").ok:
            removed += 1
            print(f"  swept playbook {m['name']} ({uuid_})")
    return removed


@scenario("wf_triggers_lifecycle")
def scenario_wf_triggers_lifecycle(s: Session) -> None:
    """Run-control + trigger-route lifecycles against playbooks we own.

    Own-things contract: the manual-input gate runs on a CLONE of the
    appliance's own "E2E - Manual Input" test playbook (renamed live-<run>-...,
    deleted at the end, inputs swept on crash); the webhook route fired is the
    clone's own route; the action trigger runs against an alert this scenario
    created and deletes. `retry` re-runs a run that ALREADY failed on its own
    (the platform's recovery action; it creates/deletes nothing). Run control
    (start / approval / resume / pause) is captured against a third run of the
    SAME clone -- start re-queues it, approval/ only lists approvals (legacy
    route), resume answers the CS-WF-48 not-paused message, and there is no
    pause/ route on 8.0.0. On 8.0.0:
      - workflow retry is a **GET** (the documented POST answers 405),
      - /api/triggers/1/deferred/{name} 404s for every route name,
      - wfinput_resume needs {input, step_iri, step_id, manual_input_id, user}
        where `user` is a /api/3/people IRI.
    """
    _ok = (200, 201, 401, 403)
    from pyfsr import FortiSOAR

    def fsr() -> FortiSOAR:
        return FortiSOAR(
            s.base, username=os.environ.get("FSR_USERNAME", ""),
            password=os.environ.get("FSR_PASSWORD", ""),
            verify_ssl=s.verify, suppress_insecure_warnings=True)

    # --- retry: newest already-failed run (GET, not the documented POST) ---
    r = s.request("POST", "/api/wf/api/workflows/log_list/",
                  params={"status": "failed", "limit": 1}, json={})
    failed = extract_members(r.json()) if r.ok else []
    if failed:
        pk = (failed[0].get("@id") or "").rstrip("/").rsplit("/", 1)[-1]
        s.call("GET", "/api/wf/api/workflows/{pk}/retry/", want=(200, 404, 405, 401, 403),
               path_params={"pk": pk}, params={"format": "json"})

    # --- manual-input lifecycle on our own clone of the E2E test playbook ---
    # Template playbooks are resolved by NAME (pack content is stable across
    # appliances; uuids are not), so this scenario ports to any 8.0.0 box.
    # Clone names include the auth mode: the (name, collection) uniqueness
    # constraint still sees a just-deleted clone in the recycle bin, so the
    # jwt and apikey passes of the same run must not collide on a name.
    E2E_NAME = "E2E - Manual Input"
    clone_uuid = None
    e2e_uuid = _find_pb_by_name(s, E2E_NAME)
    try:
        if e2e_uuid:
            clone = fsr().playbooks.clone(e2e_uuid, s.live_name(f"input-test-{s.current_auth}"),
                                          is_active=True)
            clone_uuid = clone.get("uuid")
        else:
            print(f"  template playbook {E2E_NAME!r} not found; skipping manual-input flow")

        if clone_uuid:
            st, trig = s.call("POST", "/api/triggers/1/notrigger/{workflowId}", want=_ok,
                              path_params={"workflowId": clone_uuid}, json={})
            task_id = (trig or {}).get("task_id") if isinstance(trig, dict) else None
            run_pk = _run_pk_for_task(s, task_id) if task_id else None

            row = _wait_pending_input(s, run_pk) if run_pk else None
            if row:
                mi_id = row.get("id")
                det = s.request("GET", f"/api/wf/api/manual-wf-input/{mi_id}/",
                                params={"format": "json"}).json()
                opt = ((det.get("response_mapping") or {}).get("options") or [{}])[0]
                user = _resolve_user_iri(s)
                s.call("POST", "/api/wf/api/workflows/{pk}/wfinput_resume/", want=_ok,
                       path_params={"pk": str(run_pk)}, params={"format": "json"},
                       json={"input": {}, "step_iri": opt.get("step_iri"),
                             "step_id": det.get("step_id"),
                             "manual_input_id": mi_id, "user": user})

                # second run: abandon its input via DELETE (the op under test)
                st, trig2 = s.call("POST", "/api/triggers/1/notrigger/{workflowId}", want=_ok,
                                   path_params={"workflowId": clone_uuid}, json={})
                task2 = (trig2 or {}).get("task_id") if isinstance(trig2, dict) else None
                run2 = _run_pk_for_task(s, task2) if task2 else None
                row2 = _wait_pending_input(s, run2) if run2 else None
                if row2:
                    s.call("DELETE", "/api/wf/api/manual-wf-input/{pk}/", want=(204, 401, 403, 404),
                           path_params={"pk": str(row2["id"])}, params={"format": "json"})

                # third run: run-control captures against OUR run only.
                # start/ re-queues a run (200 {task_id, url}); approval/ is the
                # LEGACY route that only LISTS approvals (200 {"approvals":
                # [...]}, it does not decide anything); resume/ on a run that
                # is not paused answers 200 with the CS-WF-48 "already been
                # resumed" message. There is no pause/ route on 8.0.0 (404),
                # so a genuinely paused run cannot be produced via the API --
                # the resume capture documents the non-paused shape.
                st, trig3 = s.call("POST", "/api/triggers/1/notrigger/{workflowId}", want=_ok,
                                   path_params={"workflowId": clone_uuid}, json={})
                task3 = (trig3 or {}).get("task_id") if isinstance(trig3, dict) else None
                run3 = _run_pk_for_task(s, task3) if task3 else None
                if run3:
                    s.call("POST", "/api/wf/api/workflows/{pk}/start/", want=_ok,
                           path_params={"pk": str(run3)}, json={})
                    s.call("POST", "/api/wf/api/workflows/{pk}/approval/", want=_ok,
                           path_params={"pk": str(run3)},
                           json={"decision": "approve", "comment": "live-test run control"})
                    s.call("POST", "/api/wf/api/workflows/{pk}/resume/", want=_ok,
                           path_params={"pk": str(run3)}, json={})
                    s.call("POST", "/api/wf/api/workflows/{pk}/pause/", want=(200, 400, 404, 405, 401, 403),
                           path_params={"pk": str(run3)}, json={})
    finally:
        if clone_uuid:
            s.request("DELETE", f"/api/3/workflows/{clone_uuid}")

    # --- webhook route: clone the API-endpoint test playbook, fire OUR route ---
    API_TEST_NAME = "FortiSOAR Playbook API test 2"
    route_name = f"live{s.run_id}{s.current_auth}route"
    web_uuid = None
    try:
        api_test_uuid = _find_pb_by_name(s, API_TEST_NAME)
        web = fsr().playbooks.clone(api_test_uuid, s.live_name(f"webhook-{s.current_auth}"),
                                    is_active=True,
                                    transform=lambda b: _set_route(b, route_name)) \
            if api_test_uuid else None
        web_uuid = web.get("uuid") if web else None
        if web_uuid:
            s.call("POST", "/api/triggers/1/{name}", want=(200, 404, 401, 403),
                   path_params={"name": route_name}, json={})
        else:
            print(f"  template playbook {API_TEST_NAME!r} not found; skipping webhook flow")
    finally:
        if web_uuid:
            s.request("DELETE", f"/api/3/workflows/{web_uuid}")

    # --- action route: clone the export playbook, run it on OUR alert -------
    EXPORT_NAME = "Export Records As CSV"
    act_uuid = None
    alert_iri = None
    try:
        export_uuid = _find_pb_by_name(s, EXPORT_NAME)
        act = fsr().playbooks.clone(export_uuid, s.live_name(f"action-pb-{s.current_auth}"),
                                    is_active=True) if export_uuid else None
        act_uuid = act.get("uuid") if act else None
        if act_uuid:
            st, created = s.call("POST", "/api/3/alerts", want=_ok,
                                 json={"name": s.live_name("action"), "source": "live_test"})
            if isinstance(created, dict):
                alert_iri = created.get("@id")
            route = _action_route(s, act_uuid)
            if route and alert_iri:
                s.call("POST", "/api/triggers/1/action/{routeUuid}", want=_ok,
                       path_params={"routeUuid": route},
                       json={"singleRecordExecution": True, "__resource": "alerts",
                             "records": [alert_iri], "__uuid": act_uuid})
        else:
            print(f"  template playbook {EXPORT_NAME!r} not found; skipping action flow")
    finally:
        if alert_iri:
            s.request("DELETE", alert_iri)
        if act_uuid:
            s.request("DELETE", f"/api/3/workflows/{act_uuid}")


def _find_pb_by_name(s: Session, name: str) -> str | None:
    """A playbook uuid by exact name (pack templates are stable; uuids are not)."""
    r = s.request("GET", "/api/3/workflows", params={"name": name, "$limit": 10})
    for m in extract_members(r.json()) if r.ok else []:
        if m.get("name") == name:
            return m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
    return None


def _RUN_IDHolder(s: Session) -> None:  # noqa: ARG001 - placeholder, kept for name stability
    return None


def _set_route(body: dict, route_name: str) -> dict:
    """Clone transform: point the (api_call) trigger step's route at ours."""
    for step in body.get("steps") or []:
        args = step.get("arguments") if isinstance(step.get("arguments"), dict) else {}
        if "route" in args:
            args["route"] = route_name
    return body


def _run_pk_for_task(s: Session, task_id: str) -> str | None:
    for _ in range(6):  # the run registers a beat after the trigger returns
        r = s.request("POST", "/api/wf/api/workflows/log_list/",
                      params={"task_id": task_id, "limit": 1}, json={})
        rows = extract_members(r.json()) if r.ok else []
        if rows:
            return str((rows[0].get("@id") or "").rstrip("/").rsplit("/", 1)[-1])
        time.sleep(2)
    return None


def _wait_pending_input(s: Session, run_pk: str, tries: int = 20) -> dict | None:
    for _ in range(tries):
        r = s.request("GET", "/api/wf/api/manual-wf-input/",
                      params={"format": "json", "limit": 50})
        rows = r.json() if r.ok else []
        rows = rows if isinstance(rows, list) else (rows or {}).get("hydra:member") or []
        for row in rows:
            if str(row.get("workflow")) == str(run_pk):
                return row
        time.sleep(3)
    return None


def _resolve_user_iri(s: Session) -> str | None:
    r = s.request("GET", "/api/3/people", params={"$limit": 50})
    members = [m for m in extract_members(r.json()) if r.ok]
    for m in members:  # prefer an admin (same recipe as pyfsr)
        name = f"{m.get('firstname') or ''} {m.get('lastname') or ''}".lower()
        if "admin" in name:
            return m["@id"]
    return members[0]["@id"] if members else None


def _action_route(s: Session, pb_uuid: str) -> str | None:
    r = s.request("GET", f"/api/3/workflows/{pb_uuid}", params={"$relationships": "true"})
    ts = (r.json() or {}).get("triggerStep") if r.ok else None
    if isinstance(ts, str) and ts.startswith("/api/3/workflow_steps/"):
        ts = s.request("GET", ts).json()
    if isinstance(ts, dict):
        return (ts.get("arguments") or {}).get("route")
    return None


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
    _, cols = s.call("GET", "/api/taxii/1/collections", want=200)
    collections = (cols or {}).get("collections") or []
    assert collections, "no TAXII collections returned"

    def _pick_nonempty(colls):
        for c in colls:
            uid = c.get("uuid") or c.get("id")
            if not uid:
                continue
            # Use raw `request` so this probe doesn't overwrite the recorded
            # observation for the {uuid} objects op.
            r = s.request("GET", f"/api/taxii/1/collections/{uid}/objects",
                          params={"limit": 1})
            if r.status_code != 200:
                continue
            try:
                body = r.json()
            except ValueError:
                continue
            total = (body or {}).get("totalItems")
            objs = (body or {}).get("objects") or []
            if (isinstance(total, int) and total > 0) or objs:
                return uid, total if isinstance(total, int) else len(objs)
        return None, 0

    cid, count = _pick_nonempty(collections)
    if not cid:
        # Every collection is empty -- seed one indicator via the ingest-feeds
        # API and re-list so the TAXII reads exercise a non-empty corpus.
        print("[taxii] all collections empty; seeding via /api/ingest-feeds/indicators")
        s.request("POST", "/api/ingest-feeds/indicators",
                  json=[{"value": "198.51.100.42", "type": "IP Address",
                         "source": "live-test", "reputation": "Suspicious"}])
        r = s.request("GET", "/api/taxii/1/collections")
        try:
            cols2 = r.json() if r.status_code == 200 else {}
        except ValueError:
            cols2 = {}
        cid, count = _pick_nonempty((cols2 or {}).get("collections") or [])
    if not cid:
        # Still nothing -- fall back to the first collection so the rest of the
        # scenario still records coverage, even if objects/ comes back empty.
        cid = collections[0].get("uuid") or collections[0].get("id")
        count = 0
    assert cid, "no uuid on any TAXII collection"
    print(f"[taxii] using collection {cid} ({count} objects)")
    s.call("GET", "/api/taxii/1/collections/{uuid}", want=200,
           path_params={"uuid": cid})

    print("[taxii] objects + manifest")
    _, objs_body = s.call("GET", "/api/taxii/1/collections/{uuid}/objects",
                          want=200, path_params={"uuid": cid},
                          params={"limit": 2})
    # Pull a real STIX id from the listing so the single-object fetch returns
    # a populated bundle instead of an empty `{totalItems: 0, objects: []}`.
    listed = (objs_body or {}).get("objects") or []
    stix_id = next((o.get("id") for o in listed if o.get("id")),
                   "indicator--11111111-1111-1111-1111-111111111111")
    s.call("GET", "/api/taxii/1/collections/{uuid}/objects/{stixId}", want=200,
           path_params={"uuid": cid, "stixId": stix_id})
    s.call("GET", "/api/taxii/1/collections/{uuid}/manifest", want=200,
           path_params={"uuid": cid}, params={"limit": 2})

    # FortiSOAR's TAXII server is read-only on this build: POST returns 404
    # (no route), not 405 -- so we don't claim a POST operation in the spec.

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


def _picklist_iri(s: Session, taxonomy: str, value: str) -> str | None:
    """Resolve the IRI of one specific picklist value (e.g. ("Severity", "High"))."""
    r = s.request("GET", "/api/3/picklist_names", params={"name": taxonomy, "$limit": 1})
    if not r.ok:
        return None
    members = (r.json() or {}).get("hydra:member") or []
    if not members:
        return None
    pln_iri = members[0].get("@id")
    rr = s.request("GET", "/api/3/picklists", params={"listName": pln_iri, "$limit": 100})
    if not rr.ok:
        return None
    for pmem in (rr.json() or {}).get("hydra:member") or []:
        if pmem.get("itemValue") == value:
            return pmem.get("@id")
    return None


def _sweep_picklists(s: Session) -> int:
    """Delete custom picklists (values first) whose list name starts with LIVE_PREFIX."""
    removed = 0
    r = s.request("GET", "/api/3/picklist_names", params={"$limit": 200})
    if not r.ok:
        return 0
    for m in extract_members(r.json()):
        name = m.get("name") or ""
        if not name.startswith(LIVE_PREFIX):
            continue
        pln_iri = m.get("@id") or ""
        uuid_ = m.get("uuid") or pln_iri.rsplit("/", 1)[-1]
        if pln_iri:
            rr = s.request("GET", "/api/3/picklists", params={"listName": pln_iri, "$limit": 200})
            for v in extract_members(rr.json() if rr.ok else {}):
                v_iri = v.get("@id")
                if v_iri and s.request("DELETE", v_iri).ok:
                    removed += 1
        if uuid_ and s.request("DELETE", f"/api/3/picklist_names/{uuid_}").ok:
            removed += 1
            print(f"  swept picklist {name} ({uuid_})")
    return removed


def _sweep_mcp_configs(s: Session) -> int:
    """DELETE /api/3/mcp_configurations/{uuid} for any config named live-*."""
    return _sweep_named(s, "/api/3/mcp_configurations", "mcp configuration")


def _sweep_scheduled(s: Session) -> int:
    """DELETE /api/wf/api/scheduled/{id}/ for tasks named live-*.

    The `{id}` is a per-request Fernet token, so it must be read from a fresh
    list call immediately before each DELETE.
    """
    removed = 0
    r = s.request("GET", "/api/wf/api/scheduled/", params={"limit": 200})
    if not r.ok:
        return 0
    body = r.json()
    members = body if isinstance(body, list) else extract_members(body)
    for m in members:
        name = m.get("name") or ""
        if not name.startswith(LIVE_PREFIX):
            continue
        tid = m.get("id")
        if tid and s.request("DELETE", f"/api/wf/api/scheduled/{tid}/").ok:
            removed += 1
            print(f"  swept scheduled task {name}")
    return removed


def _sweep_indicators(s: Session) -> int:
    """DELETE indicators whose `value` carries the LIVE_PREFIX marker."""
    removed = 0
    r = s.request("GET", "/api/3/indicators", params={"$search": LIVE_PREFIX, "$limit": 200})
    if not r.ok:
        return 0
    for m in extract_members(r.json()):
        if LIVE_PREFIX not in (m.get("value") or ""):
            continue
        uuid_ = m.get("uuid") or (m.get("@id", "").rsplit("/", 1)[-1])
        if uuid_ and s.request("DELETE", f"/api/3/indicators/{uuid_}").ok:
            removed += 1
            print(f"  swept indicator {m['value']}")
    return removed


@scenario("agents_lifecycle")
def scenario_agents_lifecycle(s: Session) -> None:
    """Routers + agent record + installer download, then cleanup.

    The flow mirrors what the lab-agent provisioner does:
      1. GET /api/3/routers          -- read the SME router IRI + CA PEM.
      2. GET /api/3/agents/{self}    -- read the appliance's Self agent
         (uuid is a hardcoded Doctrine fixture).
      3. POST /api/3/agents          -- create a throwaway lab record.
      4. GET /api/3/agents/{uuid}    -- poll health.
      5. POST /api/integration/agent-installer/ -- request the .bin (probe).
      6. DELETE /api/3/agents/{uuid} -- cleanup.

    Skipped (not failed) on appliances where SME isn't enabled: the routers
    list is empty, so there is no IRI to pass to POST /api/3/agents. The
    installer download is exercised with the response binary read but not
    persisted -- scenarios that download large blobs would otherwise blow
    out the captured-examples store.
    """
    SELF_AGENT_UUID = "973c17df-bb4b-41e5-b59c-a408666fdf27"
    BASH_INSTALLER_IRI = "/api/3/picklists/a8181039-30a0-4807-b470-50de69d37561"

    print("[agents] step 1: list routers")
    _, routers = s.call("GET", "/api/3/routers", want=200, params={"$limit": 1})
    members = (routers or {}).get("hydra:member") or []
    if not members:
        print("[agents] no SME router configured -- skipping create/delete probes")
        return
    router_iri = members[0].get("@id")
    assert router_iri, f"router has no @id: {members[0]}"

    print(f"[agents] step 2: read Self agent ({SELF_AGENT_UUID})")
    s.call("GET", "/api/3/agents/{uuid}", want=200,
           path_params={"uuid": SELF_AGENT_UUID})

    print("[agents] step 3: list agents")
    s.call("GET", "/api/3/agents", want=200, params={"$limit": 5})

    print("[agents] step 4: create throwaway agent record")
    name = s.live_name("agent")
    _, created = s.call("POST", "/api/3/agents", want=(200, 201),
                        json={"name": name, "router": router_iri,
                              "installerType": BASH_INSTALLER_IRI,
                              "description": f"{LIVE_PREFIX}lab-agent probe"})
    created = created or {}
    uuid_ = created.get("uuid")
    agent_id = created.get("agentId")
    assert uuid_ and agent_id, f"create response missing uuid/agentId: {created}"
    s.track("agent", uuid_)
    print(f"  created uuid={uuid_} agentId={agent_id}")

    print("[agents] step 5: read created record (poll health once)")
    s.call("GET", "/api/3/agents/{uuid}", want=200, path_params={"uuid": uuid_})

    print("[agents] step 6: request installer .bin (binary response, not asserted)")
    # The installer endpoint returns a multi-MB binary; capture_body=False
    # records the 2xx (so the op counts as live-captured) without persisting
    # the binary into the examples store.
    s.call("POST", "/api/integration/agent-installer/",
           want=(200, 400, 401, 403, 404),
           capture_body=False,
           params={"format": "json"},
           json={"agent": agent_id, "connectors": [],
                 "include_last_known_configurations": False},
           timeout=120)

    print("[agents] step 7: probe connector-on-agent routes (read-only)")
    # These routes proxy to the remote agent over SME. With a lab agent record
    # that has no live agent VM behind it, the appliance typically responds 200
    # with an empty listing (GET) or 4xx (write paths). Accept the broad set so
    # the probes record per-auth coverage without false-failing the run.
    s.call("POST", "/api/integration/connectors/agents/{name}/{version}/",
           want=(200, 400, 404),
           path_params={"name": "hello-world", "version": "1.0.4"},
           params={"format": "json"}, json={})
    s.call("GET", "/api/integration/agent-heartbeat/{agent}/",
           want=(200, 400, 404),
           path_params={"agent": agent_id})

    print("[agents] step 7b: queue a connector install on the awaiting agent")
    # install-connector on an agent that is still "Awaiting Remote Node
    # Connection" queues the request (200, remote_status "awaiting") without
    # executing anything on a VM. The queue row is an upsert keyed on
    # (connector, version, agent), so repeated runs do not accumulate rows.
    awaiting = _awaiting_agent(s)
    version = _catalog_version(s, "cyops_utilities")
    if awaiting and version:
        s.call("POST", "/api/integration/install-connector/", want=(200, 400, 401, 403, 500),
               params={"format": "json"},
               json={"name": "cyops_utilities", "label": "cyops_utilities",
                     "version": version, "rpm_full_name": "", "category": ["Utilities"],
                     "description": "", "publisher": "Fortinet",
                     "agent": [awaiting["agentId"]]})
    else:
        print(f"  skipping install-connector (awaiting={bool(awaiting)}, version={version})")

    print("[agents] step 8: cleanup")
    r, _ = s.call("DELETE", "/api/3/agents/{uuid}", want=(204,),
                  path_params={"uuid": uuid_})
    print(f"  DELETE agent -> {r.status_code}")


# --- CLI -----------------------------------------------------------------

def main() -> int:
    """Run with a throwaway API key that mirrors the JWT user's roles and teams.

    Without it the API-key runs compare against whatever key `.env` holds; one
    with no team 403s on every write and aborts the scenario, which reads as
    "API keys don't work here". `--env-key` uses `FSR_API_KEY` as before.
    """
    if "--env-key" in sys.argv:
        sys.argv.remove("--env-key")
        return _run()
    load_dotenv(ROOT / ".env")
    from pyfsr import FortiSOAR

    from mirror_key import mirror_api_key

    jwt = FortiSOAR(os.environ["FSR_BASE_URL"], username=os.environ["FSR_USERNAME"],
                    password=os.environ["FSR_PASSWORD"],
                    verify_ssl=os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true",
                    suppress_insecure_warnings=True)
    with mirror_api_key(jwt) as key:
        return _run(key)


def save_observations(s: Session) -> tuple[int, int]:
    """Merge ``s.observations`` into the on-disk store (shape-stable freeze).

    Used by ``_run`` after a scenario pass AND by the one-off capture scripts
    under ``scripts/`` so captures land in the same store with the same merge
    semantics. Merges two levels deep: prior observations for ops we didn't
    touch this run are preserved, and prior per-auth records for ops we
    touched under one mode but not the other are also kept.

    **Shape-stable freeze:** when the prior captured body has the same
    structural shape as the fresh one (same key set at every dict, same
    types, same list element shapes), we keep the prior body and only
    update the metadata (``captured_at``, ``response_status``). This stops
    ops that capture inherently-time-varying records (the latest
    workflow run, the tail of the audit log, cpu metrics) from churning
    the diff every run. If the shape *does* change -- new field appears,
    field type flips, list element gains keys -- we replace the body so
    docs reflect the new contract.
    """
    prior: dict = {}
    if OBSERVATIONS_PATH.exists():
        try:
            prior = json.loads(OBSERVATIONS_PATH.read_text())
        except json.JSONDecodeError:
            prior = {}
    frozen = 0
    refreshed = 0
    for op_key, op_rec in s.observations.items():
        existing = prior.setdefault(op_key, {"by_auth": {}})
        existing_by_auth = existing.setdefault("by_auth", {})
        for mode, new_rec in op_rec.get("by_auth", {}).items():
            prior_rec = existing_by_auth.get(mode)
            if prior_rec is None:
                existing_by_auth[mode] = new_rec
                refreshed += 1
                continue
            prior_body = prior_rec.get("response_body")
            new_body = new_rec.get("response_body")
            if prior_body is None and new_body is not None:
                # First real body for this op (the prior capture was an error
                # status, which records no body): always replace. _same_shape
                # would call null-vs-dict "shape-compatible" (the right rule
                # for nullable FIELDS) and freeze the null forever.
                existing_by_auth[mode] = new_rec
                refreshed += 1
            elif prior_body is not None and new_body is None:
                # This run produced no body (error status) where we already
                # hold a good example: keep the prior record verbatim --
                # pairing the old body with the new error status would make
                # the docs self-contradictory, and the scenario's want
                # assertion treats the regression as a bug to fix anyway.
                frozen += 1
            elif _same_shape(prior_body, new_body):
                # Freeze: keep the prior body verbatim, refresh metadata.
                merged = dict(prior_rec)
                merged["response_status"] = new_rec.get("response_status")
                merged["captured_at"] = new_rec.get("captured_at",
                                                    prior_rec.get("captured_at"))
                if "request_body" in new_rec:
                    merged["request_body"] = new_rec["request_body"]
                existing_by_auth[mode] = merged
                frozen += 1
            else:
                existing_by_auth[mode] = new_rec
                refreshed += 1
    OBSERVATIONS_PATH.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n")
    print(f"--- observations: wrote {len(s.observations)} op(s) "
          f"(total {len(prior)}) to {OBSERVATIONS_PATH.relative_to(ROOT)} "
          f"[{frozen} shape-stable, {refreshed} refreshed] ---")
    return frozen, refreshed


def _run(api_key: str = "") -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep-only", action="store_true", help="Clean up leftover live-* records and exit.")
    ap.add_argument("--scenario", action="append", help="Run only the named scenario(s). Defaults to all.")
    ap.add_argument("--no-presweep", action="store_true", help="Skip the startup sweep.")
    ap.add_argument("--parallel", type=int, default=1, metavar="N",
                    help="Run up to N scenario/auth jobs concurrently (default 1, sequential). "
                         "Each job runs in its own cloned Session; observations/redirects are "
                         "merged back into the main session after each completes.")
    args = ap.parse_args()

    s = open_session(api_key)
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

    # Build the job list: cartesian product of selected scenarios × auth modes.
    jobs: list[tuple[str, Callable, str]] = []
    for name in targets:
        fn = SCENARIOS.get(name)
        if not fn:
            print(f"  unknown scenario: {name}", file=sys.stderr)
            failed.append(name)
            continue
        for mode in list(s.auth_modes):
            jobs.append((name, fn, mode))

    if args.parallel <= 1 or len(jobs) <= 1:
        # Sequential path -- preserves the inter-job sweep that catches any
        # records a crashed scenario left behind before the next one starts.
        for name, fn, mode in jobs:
            s.set_auth(mode)
            print(f"--- scenario: {name} (auth={mode}) ---")
            t0 = time.time()
            try:
                fn(s)
                print(f"  ok ({(time.time() - t0) * 1000:.0f} ms)")
            except Exception as exc:
                print(f"  FAILED ({mode}): {exc}", file=sys.stderr)
                failed.append(f"{name}[{mode}]")
            sweep(s)
    else:
        # Parallel path -- each job gets its own cloned Session so the auth
        # header / observations / created-records list don't race. Results
        # merge back into `s` on the main thread via `as_completed`, so no
        # locking is needed around the shared dicts.
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _worker(job_name: str, fn: Callable, mode: str) -> tuple[str, str, dict, list, list, str | None, float]:
            sess = Session(
                base=s.base, verify=s.verify, timeout=s.timeout,
                headers={**s.headers, "Authorization": s.auth_modes[mode]},
                run_id=s.run_id, host=s.host, tenant=s.tenant,
                auth_modes=s.auth_modes, current_auth=mode,
            )
            t0 = time.time()
            err: str | None = None
            try:
                fn(sess)
            except Exception as exc:
                err = str(exc)
            return (job_name, mode, sess.observations, sess.created,
                    sess.redirects, err, (time.time() - t0) * 1000)

        workers = min(args.parallel, len(jobs))
        print(f"--- parallel run: {workers} worker(s), {len(jobs)} job(s) ---")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_worker, n, fn, m) for (n, fn, m) in jobs]
            for fut in as_completed(futures):
                name, mode, obs, created, redirects, err, ms = fut.result()
                if err is None:
                    print(f"--- {name} ({mode}) ok ({ms:.0f} ms)")
                else:
                    print(f"--- {name} ({mode}) FAILED: {err}", file=sys.stderr)
                    failed.append(f"{name}[{mode}]")
                # Merge per-worker observations into the main session.
                for op_key, op_rec in obs.items():
                    existing = s.observations.setdefault(op_key, {"by_auth": {}})
                    existing.setdefault("by_auth", {}).update(op_rec.get("by_auth", {}))
                s.created.extend(created)
                s.redirects.extend(redirects)

    print("--- post-sweep ---")
    n = sweep(s)
    print(f"  removed {n} record(s)")

    if s.observations:
        OBSERVATIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Merge two levels deep: prior observations for ops we didn't touch
        # this run are preserved, and prior per-auth records for ops we
        # touched under one mode but not the other are also kept.
        save_observations(s)

    if s.redirects:
        # Dedupe on (method, url-path-only, status, location) so a route hit
        # under both auth modes shows once. Strip the base URL for readability.
        seen: set[tuple[str, str, int, str]] = set()
        rows: list[tuple[str, str, int, str]] = []
        for method, url, status, location in s.redirects:
            path = url[len(s.base):] if url.startswith(s.base) else url
            key = (method, path, status, location)
            if key in seen:
                continue
            seen.add(key)
            rows.append(key)
        print(f"\n--- redirects observed ({len(rows)} unique) ---")
        for method, path, status, location in rows:
            print(f"  {status} {method} {path}  ->  {location}")

    if failed:
        print(f"\n{len(failed)} scenario(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
