# fortisoar-api-docs

Curated, **live-tested** OpenAPI 3.1 reference for the FortiSOAR API,
rendered with [Scalar](https://scalar.com).

Every operation is hand-shaped. Where possible, each op is also hit
against a real FortiSOAR (under both Bearer JWT and API-KEY auth), and
the captured request + response bodies replace the hand-written
examples in the published spec. Ops we can't honestly verify ship with
hand-curated examples; ops we have no schema and no live capture for
ship without a fabricated response body — `spec_health.py` flags those
as a gap rather than letting fake `@context: /api/3/contexts/Record`
envelopes leak into the docs.

```
src/build_curated.py        →  build/fortisoar.curated.openapi.yaml
src/live_test.py            →  build/live_observations.json
src/spec_health.py          →  drift report (live/auth/request/response/...)
web/index.html              →  Scalar renderer (CDN)
TODOS.md                    →  what's next: coverage backlog + accuracy work
```

Spec at the time of writing: **82 ops, 67 paths, 35 live-verified.**

---

## Quick start

```bash
# 1. one-time setup
uv venv
.venv/bin/pip install -e . jsonschema

# 2. configure live FortiSOAR (see "Environment" below)
cp .env.example .env
$EDITOR .env

# 3. build, run live scenarios, rebuild with real captures
.venv/bin/python src/build_curated.py     # writes the spec
.venv/bin/python src/live_test.py         # exercises scenarios, writes observations
.venv/bin/python src/build_curated.py     # re-run: folds captures into the spec

# 4. check what's drifting
.venv/bin/python src/spec_health.py       # categorized drift report

# 5. serve
.venv/bin/python -m http.server 8765
# open http://localhost:8765/web/index.html
```

The build step is **idempotent and offline-safe** — without
`build/live_observations.json`, the spec ships with hand-curated
examples only. Live coverage is opt-in, gated on you running
`live_test.py` with a `.env`.

---

## Environment

`src/live_test.py` reads `.env` (gitignored). All values optional
except `FSR_BASE_URL` plus at least one auth method:

| Variable | Purpose |
|---|---|
| `FSR_BASE_URL` | e.g. `https://soar.example.com` (no trailing slash). Required. |
| `FSR_API_KEY` | API key minted in **Settings → Security Management → Access Keys**. Used as `Authorization: API-KEY <value>`. |
| `FSR_USERNAME` | Login id for JWT auth. |
| `FSR_PASSWORD` | Password for `POST /auth/authenticate`. **Never `source .env` — the password contains `$`; bash will expand it and lock the account.** Use `python-dotenv`. |
| `FSR_VERIFY_TLS` | `true` to enforce TLS verification. Default `false` (lab boxes use self-signed). |
| `FSR_TEST_TIMEOUT` | Per-request timeout in seconds. Default `20`. |
| `FSR_TENANT` | Tenant slug for multi-tenant appliances. Default `exo-ui`. |
| `FSR_HELLO_TGZ` | Path to a hello-world connector .tgz for `connector_lifecycle`. Defaults to `tests/fixtures/hello-world-1.0.4.tgz`. |

`.env.example` ships a template; copy to `.env` and fill in.

---

## How live examples are fetched

```
src/build_curated.py
    │
    │  builds the curated spec from hand-written PATHS[] + schemas
    │  _ensure_examples():     synthesize examples from declared schemas only;
    │                          NEVER fabricate @context/@id Hydra envelopes
    │  _apply_curated_examples(): overlay hand-written CURATED_EXAMPLES
    │  _apply_live_observations(): overlay live captures (highest priority)
    ▼
build/fortisoar.curated.openapi.yaml      ← what Scalar renders


src/live_test.py
    │
    │  Stateful scenarios. Each one creates → exercises → deletes
    │  resources prefixed with `live-<run-id>-…` so a crashed run
    │  gets swept on the next start.
    │
    │  Available scenarios:
    │    • smoke               — read-only + side-effect-free probes
    │    • api_keys            — full API-key lifecycle (create user,
    │                            bind scope, rename, deactivate/reactivate,
    │                            regenerate, revoke)
    │    • queries             — ad-hoc query, saved query persist (UserQuery),
    │                            persisted-query execute, global search
    │    • connector_lifecycle — install tgz → list → configure → execute
    │                            → healthcheck → uninstall
    │
    │  Each scenario runs once per auth mode the .env supports (JWT,
    │  API-KEY, or both). Per-auth observations land in:
    │
    ▼
build/live_observations.json
    │
    │  Structure: {"METHOD /path/template": {"by_auth": {
    │                "jwt":    {request_body, response_status, response_body, captured_at},
    │                "apikey": {…} | {"gated_upstream": true}
    │              }}}
    │
    │  Bodies are scrubbed before persisting:
    │    UUIDs → <uuid>, 32-hex → <self-agent>, 64-hex → <api-key>,
    │    JWTs → <jwt-token>, multipart parts → <binary>.
    ▼
next `src/build_curated.py` invocation
    │
    │  For each captured op:
    │    1. replace request example with the actual sent body (JWT-preferred)
    │    2. replace 2xx response example with the captured body
    │    3. add `x-verified-live: [jwt, apikey]` listing which modes returned 2xx
    │    4. append `**Auth coverage:** Bearer JWT: OK · API-KEY: 403` to description
    ▼
docs render with real wire shapes, per-auth coverage badges, no fabrication
```

### Auth-mode coverage

Scenarios run **once per auth mode** the `.env` supports. An op that
returns `apikey: 403` and `jwt: 200` ends up with `x-verified-live: [jwt]`
and a description footer showing both statuses, so callers can see at a
glance which modes work. Examples observed in this repo: all
`api_keys` / `auth/users` / `auth/config` admin ops are JWT-only;
`/api/wf/...` and `/api/3/*` CRUD work under either.

### Read-only by default, destructive by opt-in

Every scenario that creates resources tracks them via `s.track(...)`
and includes an explicit cleanup step. Sweepers (`_sweep_api_key_scopes`,
`_sweep_connector_configs`, `_sweep_hello_world_connectors`,
`_sweep_query_objects`, ...) run at startup and between auth modes so a
crashed prior run can't leave orphan `live-*` records behind.

```bash
.venv/bin/python src/live_test.py                      # sweep, run all scenarios, sweep
.venv/bin/python src/live_test.py --sweep-only         # just clean up leftovers
.venv/bin/python src/live_test.py --scenario smoke     # one scenario only
.venv/bin/python src/live_test.py --no-presweep        # skip the startup sweep
```

---

## `src/spec_health.py` — drift report

Categorizes inconsistencies the spec accumulates as ops are edited
piecemeal. Exits non-zero if anything is flagged.

| Category | What it surfaces |
|---|---|
| `live` | Ops not exercised by any `live_test.py` scenario. |
| `auth` | Ops verified under only one auth mode (the other was 403 / gated upstream). |
| `params` | Path-template params not declared in `parameters`. |
| `request` | POST/PUT/PATCH ops missing a `requestBody` example or schema. |
| `response` | 2xx responses with neither an example nor a schema. |
| `description` | Empty or near-empty descriptions. |
| `schema_drift` | Captured response has top-level keys outside the declared schema. |
| `placeholders` | Examples carrying unresolved `<...>` tokens (other than the intentional sanitizer set). |

```bash
.venv/bin/python src/spec_health.py                    # full report
.venv/bin/python src/spec_health.py --quiet            # just the totals line
.venv/bin/python src/spec_health.py --category=live    # one category
.venv/bin/python src/spec_health.py --max=5            # cap per-category print length
```

---

## How to add more examples

Three sources, lower priority → higher priority:

### 1. Schema-driven synthesis (the floor)

If a request/response has a `schema` (a `$ref` or inline `properties`),
`_ensure_examples()` derives an example. To nudge what gets synthesized,
add `example` / `default` / `enum` to the schema fragment:

```python
"properties": {
    "severity": {"type": "string", "example": "/api/3/picklists/<uuid>"},
    "limit":    {"type": "integer", "default": 30},
    "format":   {"type": "string",  "enum": ["json", "csv"]},
}
```

When neither schema nor example is available, the response example is
**left unset**. We do not stamp `@context: /api/3/contexts/Record` /
`@id: /api/3/<collection>/...` envelopes — that misleads readers into
thinking we've verified a shape we haven't. `spec_health response`
flags those gaps for follow-up.

### 2. Hand-curated examples (`CURATED_EXAMPLES`)

For ops `live_test.py` can't / shouldn't exercise (destructive,
needs a fixture we don't synthesize), add an entry to
`CURATED_EXAMPLES` in `src/build_curated.py`:

```python
("POST", "/api/3/import_jobs"): {
    "request": {"type": "Import Wizard", "file": "/api/3/files/<uuid>"},
    "response": {"200": {"@id": f"/api/3/import_jobs/{_UUID}", "status": "pending"}},
},
```

Use the shared placeholder UUIDs (`_UUID`, `_UUID2`, `_PB_UUID`,
`_FILE_UUID`) so cross-references stay coherent.

### 3. Live captures (override everything else)

Add a scenario step to `src/live_test.py`:

```python
@scenario("my_new_flow")
def scenario_my_new_flow(s: Session) -> None:
    _, body = s.call("POST", "/api/3/<thing>", want=(200, 201),
                     json={"name": s.live_name("foo"), ...})
    s.track("my_thing", body["uuid"])
    s.call("GET", "/api/3/<thing>/{uuid}", want=200,
           path_params={"uuid": body["uuid"]})
    # cleanup: either inline DELETE here or extend sweep() with a helper
```

Use `s.call` (not `s.request`) so requests + responses are captured
under the path template — this is what `_apply_live_observations`
uses to overlay onto the spec.

---

## Adding a new operation

1. Add the path + method to `PATHS` in `src/build_curated.py`. Set
   `tags`, `summary`, `description`, `parameters`, `requestBody`,
   `responses` — same shape as adjacent ops.
2. If the tag is new, add a `TAG_DESCRIPTIONS` entry and slot it into
   a `TAG_GROUPS` bucket.
3. (Optional) Add a `CURATED_EXAMPLES` entry if the op is destructive
   or `live_test.py` can't reach it.
4. (Optional) Add a `CROSS_LINKS` entry to point readers at a relevant
   section of the introduction prose.
5. Rebuild: `.venv/bin/python src/build_curated.py`.
6. If the op is safe to probe, add a `live_test.py` step covering it
   and rerun the scenario.
7. `python src/spec_health.py` to confirm no new gaps were introduced.

The build runs a leak scanner (`_scan_for_leaks`) over descriptions /
summaries / param docs / schema docs / security-scheme docs and fails
if it finds implementation-detail tokens (Symfony, Doctrine, Tomcat,
gunicorn, Cython, `/opt/cyops`, class names, etc.). It does **not**
scan captured request/response examples — those are real bytes the
API returned.

---

## Adding reference prose

The introduction at the top of the rendered page is `info.description`,
defined as `REFERENCE_PROSE` in `src/build_curated.py`. Headings become
anchors of the form `#description/<slug>`, which `CROSS_LINKS`
references from each op so readers can jump from an operation page
back to the relevant explainer.

To add a new section:

1. Add an `## Heading` to `REFERENCE_PROSE`.
2. Reference it from related ops via `CROSS_LINKS`:
   `"/api/3/foo": "[New section](#description/heading-slug)"`.
3. Rebuild.

---

## Gotchas

**Trailing-slash HMAC trap.** Routes outside `/api/3/` (especially
under `/api/wf/`, `/api/integration/`, `/api/gateway/`) often require
a trailing slash on the final non-templated segment. Without it the
request hits an HMAC-gated handler that returns
`403 {"detail":"Could not validate HMAC fingerprint"}` under either
auth mode — the same response a real auth failure produces. Known
instances:

- `GET /api/wf/api/workflows/count/` (no slash → 403 HMAC)
- `DELETE /api/integration/configuration/{config_id}/` (no slash → 403 HMAC)
- `DELETE /api/integration/connectors/{id}/` (no slash → 403 HMAC)

Before believing a 403 HMAC, retry the slashed form. `/api/3/`
routes are unaffected.

**Never `source .env`.** The FortiSOAR password commonly contains
`$`, which bash will expand. Use `python-dotenv` (which all the
scripts here already do).

**`/api/search` is broken on some 7.6.x builds.** Returns
`TypeError` 400 for every reasonable body shape. The spec captures
the 400 honestly; don't try to "fix" it by writing a fake 200.

---

## Troubleshooting

**"No working auth: set FSR_USERNAME+FSR_PASSWORD and/or FSR_API_KEY"**
`.env` is empty or missing. Copy from `.env.example`.

**"IMPLEMENTATION-DETAIL LEAKS in spec prose"**
The leak scanner caught a banned token in a description / summary
field. Fix the source text in `build_curated.py`. False positive?
Add the substring to `LEAK_WHITELIST_LINES`.

**Build succeeds but `spec_health` flags new gaps**
This is the intended workflow — `spec_health` is the to-do list.
Each category lists exactly which ops need attention.

**A scenario hangs**
Some appliances take a while to install solution packs. The
`connector_lifecycle` install call uses a 180-second timeout; bump
`FSR_TEST_TIMEOUT` if your appliance is slow on the rest.

---

## Layout

```
src/
  build_curated.py             curated spec generator (single source)
  live_test.py                 stateful scenarios + sweepers (writes observations)
  spec_health.py               drift report (live/auth/params/.../placeholders)
  verify_curated.py            legacy stateless verifier (kept for one-off filter runs)
  sanitize.py                  PII / cred scrubber
build/
  fortisoar.curated.openapi.yaml    generated; checked in for the renderer
  live_observations.json            generated by live_test.py
scripts/
  triage_failures.py           ad-hoc tooling for diagnosing live failures
tests/
  fixtures/                    .tgz / sample bodies used by scenarios
web/
  index.html                   Scalar wrapper (loads build/...yaml)
.env.example                   template; copy to .env
TODOS.md                       coverage backlog + accuracy work
```

See [`TODOS.md`](TODOS.md) for the prioritized backlog.
