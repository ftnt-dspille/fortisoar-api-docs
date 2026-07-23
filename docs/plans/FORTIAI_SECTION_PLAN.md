# Plan: document the FortiAI surface in the curated spec

**Goal.** A first-class AI section in the published docs covering agent
configuration, MCP server registration, running a single agent, running a full
investigation, LLM provider/config management, insights, and the knowledge base
— live-verified, with pyfsr samples.

**Status: All phases complete (2026-07-23).** The curated spec carries **64
AI/MCP paths** across 217 operations / 168 total paths. 141 ops have a pyfsr
sample. 0 bad descriptions. 14 unreachable ops are filtered. 37 AI/agent descriptions enriched from AI recon.
Live-verified on 8.0.0-6034 via `live_test.py --scenario ai`.
Decisions 2a (ungate), 2b (vendor recon), 2c (omit unreachable ops) are all done.

**Remaining:** None — section is ready for inclusion in the published docs.

---

## 0. Sourcing principle: pyfsr first, service spec second

The AI service publishes its own OpenAPI (`https://<appliance>:8001/openapi.json`,
"Autonomous SOC Analyst" 5.0.0, 55 operations). It is tempting to treat that as
the source of truth. **It is not, and building the section from it would ship
documentation for endpoints that cannot be called.**

Every `/api/ai/*` request passes through the PHP proxy (`ProxyController`),
which authorises against a permission map in the appliance's `parameters.yaml`
(`app_proxy.handlers.ai`, 38 route-regex → permission groups). A request that
matches **no** group is rejected with a bare `Access Denied` regardless of role.
Intersecting the two:

> **41 of the service's 55 operations are reachable through the front door.
> 14 are not.**

The unreachable set is not exotic — it includes the entire LLM model/provider
catalogue (`/ai/llm/model*`, `/ai/llm/provider*`), `POST /ai/agents/alert`,
`PUT /ai/agent/config`, `POST /ai/llm/config/verify`, and all four `/ai/triage/*`
task routes. Two of those are already wired into pyfsr and are therefore dead
code (see §4).

**So the ordering is:**

1. **pyfsr's `client.ai` is the spine.** 36 methods with a wired endpoint, each
   backed by live-verified request/response shapes, typed models, and in several
   cases hard-won behavioural knowledge (retry semantics, config-sync latency,
   envelope quirks). If pyfsr does it, we know it works.
2. **The service OpenAPI is the inventory and the schema donor** — it tells us
   what exists and gives us body schemas, but membership in it is not evidence
   that a caller can reach it.
3. **The permission map is the gate.** Every documented operation carries its
   required permission; anything unreachable is either omitted or explicitly
   marked as such.

An operation earns a place in the spec when it clears **two** of the three:
pyfsr wraps it, or it is reachable per the permission map and we have verified
it live.

---

## 1. What pyfsr already gives us (the spine)

36 public `client.ai` methods, spanning **four** surfaces — note that two of
them do not appear in the service OpenAPI at all, so a service-spec-first build
would have missed them entirely:

| Surface | Paths | Example methods |
|---|---|---|
| `/api/ai/*` — AI service | agent list/get/import/export/config/activate, trigger, status, result, acceptance, llm config CRUD, mcp list/validate | `list_agents`, `run_agent`, `investigate_alert`, `get_agent_config`, `activate_agent`, `create_llm_config` |
| `/api/3/mcp_configurations` — **CRUD module** | register/update/delete/list MCP servers | `register_mcp_server`, `save_mcp_server`, `upsert_mcp_server` |
| `/mcp/*` — appliance MCP gateway | connector candidates, tool export, host-connector-as-server, tool CRUD | `mcp_connector_candidates`, `host_connector_as_mcp_server`, `delete_mcp_tools` |
| `/api/3/llm_activity_logs` — **audit module** | tool-usage evidence behind a verdict | `tool_usage`, `find_investigations` |

**"MCP server creation" is `/api/3/mcp_configurations`, not `/ai/mcp`.** The AI
service only *reads and validates* registered servers. Keep the three MCP
surfaces distinct in the tag structure; conflating them is the single easiest
way to make this section confusing.

Beyond endpoints, pyfsr carries knowledge the spec should absorb:

- **Per-agent input contracts.** Each agent publishes `inputformat` — the exact
  payload for `POST /ai/agents/{name}/trigger`, with required flags and enums.
  `agent_input_schema()` reads it; `run_agent(validate=True)` enforces it.
  Document the mechanism plus two concrete shapes (`ioc-enrichment` takes
  `{question, ioc[]}`; `alert-investigation` takes `{data: <raw alert>}`).
- **Single-agent vs investigation result shapes.** A single agent returns its
  own `outputformat` (`answer`/`evidence`/`confidence`); an investigation
  returns `summary`/`hypotheses`/`phases`. pyfsr models both
  (`AgentRunResult` vs `InvestigationResult`).
- **The `/ai/triage` vs `/ai/agents` trap** (below) — found by pyfsr, fixed in
  pyfsr, and nowhere in any vendor documentation.

## 0b. What exists in this repo (as of Phase 1)

| Artifact | Where | State |
|---|---|---|
| `src/merge_ai_mcp.py` (375 lines) | tracked | permanently wired into `build_curated.py`, merges `/ai/*` + `/mcp/*` REST admin, synthesises JSON-RPC ops, hand-groups 9 tags |
| Recon sources | `src/recon/` | `fsr_ai_openapi.json`, `mcp_server_openapi.json`, `mcp_tools_live.json` — vendored, hygiene-clean |

The captured recon is accurate on 8.0.0:
55 ops, **nothing removed**, two additions over the 8.0.0 snapshot (`GET /ai/llm/allowed-providers`,
`GET /ai/mcp/status`), same service version.

---

## 2. Decisions

**2a. ~~Un-gate `FSR_AI_MCP=1`.~~ [DONE]** `merge_ai_mcp.py` is permanently
wired into `build_curated.py` (no env gate). The TODOS banner is removed.

**2b. ~~Vendor the recon sources into `src/recon/`.~~ [DONE]** Files vendored
and hygiene-scanned (zero lab IPs/creds found). Default recon path updated to
`src/recon/`; no longer depends on the external `fortisoar/fsr-ai-mcp-recon/` dir.

**2c. What to do with the 14 unreachable operations.** Recommendation: **omit
them from the spec**, and add one paragraph to the AI tag description explaining
that the service exposes routes the front door does not authorise, with the
`/ai/triage` re-mount as the worked example. Documenting an endpoint nobody can
call is worse than silence — but the *reason* is genuinely useful. (Alternative:
include them marked `deprecated: true` with an explanation. Decide when writing;
omission is cleaner.)

---

## 3. Tag structure

| Tag | Covers | Source |
|---|---|---|
| **AI Agents** | agent management: list, get, import/export, config, default config, activate | pyfsr + spec |
| **AI Agent Execution** | trigger one agent, start investigation, status, result, acceptance | pyfsr + spec |
| **AI LLM** | providers (`allowed-providers`), config CRUD | pyfsr + spec (model/provider catalogue omitted — unreachable) |
| **AI MCP Registry** | `/ai/mcp`, `/ai/mcp/validate`, `/ai/mcp/status` | pyfsr + spec |
| **MCP Configurations** | `/api/3/mcp_configurations` CRUD — where servers are actually created | **pyfsr only** |
| **MCP Gateway** | `/mcp/*` — connector candidates, tool export, host-connector, tool CRUD | **pyfsr only** |
| **MCP Tools** | `/mcp/{modules,playbooks,utility,connector/{name}}/` JSON-RPC | synthesised |
| **AI Insight** | `/ai/insight/*` — plans, chain-of-thought, execute, schedule | spec only (reachable; verify live) |
| **AI Enrichment** | `/ai/enrich/*` — knowledge base / context index | spec only (reachable; verify live) |
| **AI Chat** | `/ai/chat/` — conversational investigation | spec only (reachable; verify live) |
| **AI Activity** | `/api/3/llm_activity_logs` — tool-usage evidence | **pyfsr only** |

Splitting agent management from execution keeps either tag from becoming the
spec's largest (19 ops combined).

---

## 4. Phases

### Phase 1 — machinery (half day)
1. ~~[DONE] Recover `merge_ai_mcp.py` from `8136ba6`; restore the `main()` hook from
   `stash@{0}` minus the env gate (2a); delete the TODOS banner.~~
2. ~~[DONE] Vendor recon JSONs into `src/recon/` (2b), re-running the hygiene scan.~~
3. Add the **reachability filter**: parse the permission map, drop or flag
   operations that match no group. Ship the map as data (`src/recon/ai_permissions.json`)
   so the filter is reproducible without an appliance.
4. Add `scripts/refresh_ai_spec.py` — pull `:8001/openapi.json` + the permission
   map from an appliance, diff against the vendored copies, fail loudly on
   drift. Prevents the rot that hit the old `schema.json` snapshot.

### Phase 2 — the pyfsr-derived layer (the differentiator)
1. **Permission line on every AI operation** (`execute.ai_agents`,
   `read.insights`, `create.llm_configurations`, …). Nothing else in the spec
   documents permissions, and a missing permission is indistinguishable from a
   wrong path — both return a bare `Access Denied`.
2. **The `/ai/triage` vs `/ai/agents` trap**, in the tag description: the service
   mounts one router under both prefixes so its OpenAPI lists both as equals,
   but only `^agents?/(.*)/trigger` is authorised. Note the asymmetry —
   `POST /ai/triage/alert` **is** authorised, so the prefix is not uniformly
   wrong, which is exactly why this bites.
3. **The pyfsr-only surfaces** (`/api/3/mcp_configurations`, `/mcp/*`,
   `/api/3/llm_activity_logs`) — absent from the service spec, so they must be
   hand-authored from pyfsr's models and live captures.
4. **Per-agent `inputformat`** as the documented way to build a trigger payload.

### Phase 3 — descriptions, examples, samples
1. Tag descriptions: installed-vs-active agents, config vs default config,
   single-agent vs investigation, and the three-way MCP split.
2. `x-codeSamples` from pyfsr for every path it wraps (project convention).
3. Response examples captured live and sanitised: single-agent result,
   investigation result, agent record with `inputformat`, MCP validate result.
4. Override the service's generic FastAPI summaries — it ships "Get Config By
   Id" on a DELETE and two different operations both called "Start Triage".

### Phase 4 — verify and publish
1. `verify_curated.py` / `live_test.py` over the read-only AI paths; mark
   verified ops so they earn the live-verified badge.
2. `spec_health.py` clean, `pytest` green, rebuild, push (Pages deploys on merge).
3. Fetch the published spec and assert the AI tags landed.

---

## 5. Feeding back into pyfsr

This intersection surfaced defects in pyfsr; they are tracked there, not here.
See `pyfsr/docs/plans/AI_SURFACE_FOLLOWUP.md`. Headlines:

- `list_models()` → `/api/ai/llm/models` and `test_llm_config()` → `/api/ai/llm/test`
  hit routes the proxy authorises nowhere. Confirmed 403 live.
- `run_agent()` used `/ai/triage/{name}/trigger` — same bug class, **fixed**.
- pyfsr wraps 18 of 49 distinct AI paths; the Insight, Enrichment and Chat
  surfaces are entirely unwrapped.

---

## 6. Effort

Phase 1 half a day. Phase 2 half a day (the data is captured). Phase 3 is the
long pole — one to two days depending on how many live response examples we
take. Phase 4 an hour. Phase 3 is also what makes this better than the vendor's
own documentation, which does not cover `/api/ai/*` at all.
