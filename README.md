# fortisoar-api-docs

Curated, **live-tested** OpenAPI 3.1 reference for the FortiSOAR API,
rendered with [Scalar](https://scalar.com).

Every operation is hand-shaped. Every operation that can be exercised
read-only is also hit against a real FortiSOAR (under both API key and
JWT auth) and the captured request + response bodies are folded back
into the spec as the rendered example.

```
src/build_curated.py        →  build/fortisoar.curated.openapi.yaml
src/verify_curated.py       →  build/curated_verification.json
web/index.html              →  Scalar renderer (CDN)
TODOS.md                    →  what's next, gap analysis vs source markdown
```

---

## Quick start

```bash
# 1. one-time setup
uv venv
.venv/bin/pip install -e . jsonschema

# 2. configure live FortiSOAR (see "Environment" below)
cp .env.example .env
$EDITOR .env

# 3. build, verify against a live FSR, rebuild with real captures
.venv/bin/python src/build_curated.py     # writes the spec (curated examples)
.venv/bin/python src/verify_curated.py    # hits each op live, writes verification.json
.venv/bin/python src/build_curated.py     # re-run: folds captures into the spec

# 4. serve
.venv/bin/python -m http.server 8765
# open http://localhost:8765/web/index.html
```

The build step is **idempotent and offline-safe** — if there's no
verification report, the spec ships with hand-curated examples.
Verification is opt-in, and only happens when you have a `.env` and run
`verify_curated.py`.

---

## Environment

`src/verify_curated.py` reads `.env` (gitignored). All values optional
except `FSR_BASE_URL` plus at least one auth method:

| Variable | Purpose |
|---|---|
| `FSR_BASE_URL` | e.g. `https://soar.example.com` (no trailing slash). Required. |
| `FSR_API_KEY` | API key minted in Settings → Security Management → Access Keys. Used as `Authorization: API-KEY <value>`. |
| `FSR_USERNAME` | Login id for JWT auth. |
| `FSR_PASSWORD` | Password for `POST /auth/authenticate`. |
| `FSR_VERIFY_TLS` | `true` to enforce TLS verification. Default `false` (lab boxes use self-signed). |
| `FSR_TEST_TIMEOUT` | Per-request timeout in seconds. Default `20`. |

`.env.example` ships a template; copy to `.env` and fill in.

---

## How the live examples are fetched

```
                          ┌─────────────────────────────────┐
src/build_curated.py ───► │ build/fortisoar.curated.openapi │ ◄── _ensure_examples()
   |                      │   .yaml (curated examples)      │     fills missing examples
   |                      └─────────────────────────────────┘
   ▼
src/verify_curated.py
   │
   │  for each operation in the spec:
   │    ┌─ build path:    fill {uuid}/{collection} from harvest or fallback
   │    ├─ build params:  schema `default` per query param (illustrative `example` values are doc artifacts and not sent — they spam list endpoints with bogus filter combos)
   │    ├─ build body:    request example from the spec (when method ∈ POST/PUT)
   │    └─ skip if mutating + read-only mode
   │
   │  for each auth mode (apikey, jwt — both if both creds set):
   │    ┌─ apikey:  Authorization: API-KEY <FSR_API_KEY>
   │    └─ jwt:     POST /auth/authenticate first, then Authorization: Bearer <token>
   │
   │  send the request, capture:
   │    - status code, elapsed ms
   │    - sent_request:  { method, path, params, body }
   │    - sample_response (sanitized via src/sanitize.py)
   │    - schema_ok / schema_errors (jsonschema vs documented 2xx schema)
   │
   ▼
build/curated_verification.json     ◄── per-op, per-auth record (gitignored)
   │
   │  next build:  src/build_curated.py
   │
   │   _merge_verification(SPEC):
   │     for each op the verifier exercised successfully (2xx in any auth mode):
   │       1. prepend  **Live-verified** (apikey: 200 - jwt: 200, https://...)
   │          to the description
   │       2. replace the request example with the actual body that produced
   │          the captured response
   │       3. replace the 2xx response example with the captured response
   │          (lists in `hydra:member` / `content` / `data` / `results` / `items`
   │          truncated to 2 items + a "<N more truncated>" marker)
   │       4. stamp `parameters[].example` with the actually-sent value for
   │          each query param
   │
   ▼
build/fortisoar.curated.openapi.yaml      ◄── what Scalar renders
```

### Auth-mode coverage

`verify_curated.py` runs **both** auth modes when both credentials are
present and records the result of each. This produces useful drift
data: an op that returns `apikey: 403, jwt: 200` is JWT-only on the
tested box, and the rendered description says so. Examples observed
on FSR 7.6.5: `/api/auth/cluster/health` and `/api/auth/license` are
JWT-only; most CRUD on `/api/3/*` works with either.

To run with **only** an API key, leave `FSR_USERNAME` / `FSR_PASSWORD`
unset. To run with only JWT, leave `FSR_API_KEY` unset. The verifier
will fail loudly if neither is set.

### Read-only by default

`verify_curated.py` skips DELETE, PUT, and the well-known mutating POST
prefixes — see `MUTATING_PREFIXES` in `src/verify_curated.py` for the
canonical list. As of 2026-05-10 it includes:

- `/auth/authenticate` (we already auth at startup; example carries
  scrubbed creds)
- `/api/3/alerts`, `/api/3/{collection}` (record creates — would need
  real picklist IRIs we don't synthesize)
- `/api/triggers/`, `/api/3/import_jobs`, `/api/3/export_jobs`,
  `/api/3/cache_util`, `/api/integration/execute`,
  `/api/wf/api/workflows/{pk}/start|resume|retry|approval`,
  `/api/ingest-feeds/`, `/api/insert-feeds/`, `/api/3/insert/`,
  `/api/3/update/`, `/api/3/delete/`, `/api/3/upsert/`,
  `/api/3/bulkupsert/`, `/api/3/api_keys`, `/api/3/files/`,
  `/api/3/logout`, `/api/gateway/audit/activities/ttl`

Pass `--include-mutating` to exercise everything against a **disposable**
FortiSOAR. Don't point it at production.

```bash
.venv/bin/python src/verify_curated.py --include-mutating
.venv/bin/python src/verify_curated.py --filter /api/version  # just one op
```

---

## How to add more examples

There are **three** places examples come from, in priority order. The
build merges them in this order, so later sources override earlier ones.

### 1. Hand-curated examples (always present, the floor)

For ops the verifier can't exercise (mutating in read-only mode, no
fixture for path placeholders, side-effects you don't want), add an
entry to `CURATED_EXAMPLES` in `src/build_curated.py`:

```python
("POST", "/api/3/api_keys"): {
    "request": {"name": "ci-pipeline-prod", "expiresOn": 1767225600,
                 "appliance": "/api/3/appliances/<uuid>"},
    "response": {"201": {
        "@id": f"/api/3/api_keys/{_UUID}", "uuid": _UUID,
        "name": "ci-pipeline-prod",
        "key": "REDACTED-ONLY-SHOWN-ONCE-ON-CREATE",  # pragma: allowlist secret
        "expiresOn": 1767225600, "createDate": 1736380800,
    }},
},
```

Keys:

- `request` (optional) — the JSON body to show under "Request example".
- `response[<code>]` — example response keyed by HTTP status. `None`
  means "no body" (used for 204).

Use the shared placeholder UUIDs (`_UUID`, `_UUID2`, `_PB_UUID`,
`_FILE_UUID`) so cross-references between examples stay coherent.

### 2. Inline schema examples (the synthesizer fallback)

If a request body doesn't get a curated example and isn't live-captured,
`_ensure_examples()` synthesizes one from the operation's
`requestBody.content.application/json.schema`. Same for responses. To
nudge what gets synthesized, add an `example` (or `default`, or `enum`)
to the schema fragment:

```python
"properties": {
    "severity": {"type": "string", "example": "/api/3/picklists/<uuid>"},
    "limit":    {"type": "integer", "default": 30},
    "format":   {"type": "string",  "enum": ["json", "csv"]},
}
```

The synthesizer is a fallback — prefer hand-curated examples for
anything customer-facing.

### 3. Live captures (overrides curated when the verifier succeeds)

Run `verify_curated.py` against an FSR. For every op that returns 2xx,
the next `build_curated.py` invocation replaces the request body
example with what was sent, the response example with what came back
(lists truncated to 2 items), and the parameter `example` fields with
the actually-sent values.

To grow live coverage:

- **Add fixtures.** Today the verifier harvests one UUID from the first
  list response it sees and re-uses it everywhere. To exercise
  `/api/3/picklists/{uuid}`, `/api/3/picklist_names/{uuid}`,
  `/api/wf/api/workflows/{pk}/...`, etc. with real ids, build a
  per-collection fixture map and feed it into `_fill_path()`. (Tracked
  in `TODOS.md` C2.)
- **Add a query-param example.** If a param is missing a `default` /
  `example` / `enum`, the verifier won't send it. Add one to the
  parameter definition and re-verify.
- **Capture mutating ops** by running with `--include-mutating`
  against a disposable FSR. The captured `(METHOD, PATH)` will then
  override any hand-curated entry on subsequent builds.

---

## Adding a new operation

1. Add the path + method to `PATHS` in `src/build_curated.py`. Set
   `tags`, `summary`, `description`, `parameters`, `requestBody`,
   `responses` — same shape as adjacent ops in the file.
2. If the op fits a tag that already exists, you're done; if not, add
   a new tag entry to `TAG_DESCRIPTIONS` and slot it into a
   `TAG_GROUPS` bucket.
3. (Optional) Add a `CURATED_EXAMPLES` entry if the op is mutating or
   the verifier can't reach it.
4. (Optional) Add a `CROSS_LINKS` entry to point readers at a
   relevant section of the introduction prose.
5. Rebuild: `.venv/bin/python src/build_curated.py`.
6. Verify: `.venv/bin/python src/verify_curated.py --filter <path>`.
7. Rebuild once more so the live-verified badge folds into the spec.

The build runs a **leak scanner** at the end (`_scan_for_leaks`) over
descriptions/summaries/parameter docs/schema docs/security-scheme docs.
It does **not** scan captured request/response examples — those are real
bytes the API returned and are not ours to rewrite. If you reintroduce
implementation-detail tokens (Symfony, Doctrine, Tomcat, gunicorn,
Cython, `/opt/cyops`, class names, etc.), the build fails with a
precise location.

---

## Adding reference prose

The introduction at the top of the page is `info.description`, defined
as `REFERENCE_PROSE` in `src/build_curated.py`. Scalar renders it
full-width in the introduction pane (CSS in `web/index.html` widens it
further). Headings become anchors of the form `#description/<slug>`,
which `CROSS_LINKS` references from each op so readers can jump from
an operation page back to the relevant explainer.

To add a new section:

1. Add an `## Heading` to `REFERENCE_PROSE`.
2. Reference it from related ops via `CROSS_LINKS`:
   `"/api/3/foo": "[New section](#description/heading-slug)"`.
3. Rebuild.

Scalar slugifies headings as lower-case-hyphens. Verify the anchor by
opening the rendered page and clicking the heading link.

---

## Troubleshooting

**"jwt fetch failed: ... NameResolutionError"**
DNS / network blip on the FortiSOAR you configured. The build itself
is unaffected — the previous `curated_verification.json` is preserved
unless you re-run the verifier and clobber it. Re-run when network is
back.

**"Need at least one of FSR_API_KEY or FSR_USERNAME+FSR_PASSWORD"**
`.env` is empty or missing. Copy from `.env.example`.

**"IMPLEMENTATION-DETAIL LEAKS in spec prose"**
The leak scanner (TODOS C3.5) caught a banned token in a description
or summary field. Fix the source text in `build_curated.py`. False
positive? Add the substring to `LEAK_WHITELIST_LINES`.

**Build is fast but verification is slow / times out**
The full sweep is ~60 ops × 2 auth modes × ~400ms = ~50s. Use
`--filter <path-substring>` to scope down during development.

**Live capture has implementation details in it (process cmdlines, etc.)**
The verifier surfaces real responses as-is. For endpoints that leak
through their captures (e.g. `/api/auth/cluster/health`), prefer the
hand-curated `CURATED_EXAMPLES` entry — but be aware that successful
live capture currently overrides it. Tracked in TODOS C3.5 (per-op
`x-fsr-redact-response: true` extension).

---

## Layout

```
src/
  build_curated.py             curated spec generator (single source)
  verify_curated.py            live-test runner (writes verification.json)
  sanitize.py                  PII / cred scrubber (used by verifier)
build/
  fortisoar.curated.openapi.yaml    generated; do not edit
  curated_verification.json         generated; gitignored
web/
  index.html                   Scalar wrapper (loads build/...yaml)
.env.example                   template; copy to .env
TODOS.md                       phased follow-ups + source-coverage gap analysis
```

See [`TODOS.md`](TODOS.md) for the prioritized backlog: C2 (verifier
hardening), C3.5 (implementation-detail leak sweep — landed),
C3.6 (offline status taxonomy), C3.7 (workflow-from-task-id how-to),
C3.8 (high-value content additions), C3.9 (gap analysis vs source
markdown), C4 (source-coverage expansion).
