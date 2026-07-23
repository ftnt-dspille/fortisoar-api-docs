"""Merge the FortiSOAR 8.0 AI + MCP surface into the curated OpenAPI spec.

Wired permanently into `build_curated.py` — called unconditionally.
Sources: vendored live OpenAPI dumps + MCP tool introspection in
`src/recon/`.  Refresh: re-pull from an 8.0+ appliance, overwrite the
JSONs, and re-run `build_curated.py`.

Four surfaces are folded in:

  1. `/ai/*` — filtered from `fsr_ai_openapi.json` (55 ops, ~14 unreachable
     through the front-door proxy). Hand-grouped into 7 AI tags.
  2. `/mcp/* REST admin` — 6 endpoints from `mcp_server_openapi.json`,
     tagged "MCP Admin".
  3. `/mcp/{modules,playbooks,utility,connector/{name}}/` — MCP streamable-HTTP
     endpoints, not OpenAPI. Synthesized into placeholder POST operations,
     tagged "MCP Tools".
  4. Pyfsr-only surfaces — `/api/3/mcp_configurations`, `/mcp/servers/connector`,
     `/mcp/config/export`, `/mcp/add/tools`, `/mcp/tools/{uuid}`,
     `/api/3/llm_activity_logs` — absent from the AI service OpenAPI, must be
     hand-authored from pyfsr's typed wrappers.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Vendored recon sources — live OpenAPI + MCP tool dumps from 8.0.0.
_RECON_DIR = Path(__file__).resolve().parent / "recon"


def _recon_dir() -> Path:
    p = _RECON_DIR
    if not p.is_dir():
        raise FileNotFoundError(
            f"AI/MCP recon dir not found: {p}. "
            "Run `cp Miscellaneous/fortisoar/fsr-ai-mcp-recon/*.json src/recon/` "
            "to restore, or pull directly from an 8.0+ appliance."
        )
    return p


# ---------------------------------------------------------------------------
# Reachability filter — the PHP proxy (ProxyController) only authorises
# certain route-regex patterns in `parameters.yaml` (`app_proxy.handlers.ai`).
# Operations matching no group return a bare `Access Denied` 403, regardless
# of role.  The list below is the complement: ops the service OpenAPI exposes
# but the front door does not authorise.  Omit them from the curated spec.
#
# The `/ai/triage` vs `/ai/agents` trap: the service mounts one router under
# both prefixes so its OpenAPI lists both as equals, but only
# `^agents?/(.*)/trigger` is authorised.  Note the asymmetry —
# `POST /ai/triage/alert` IS authorised, so the prefix is not uniformly wrong,
# which is exactly why this bites.  We keep `/ai/triage/alert` and drop the
# four /ai/triage/{task_id}/* routes.
# ---------------------------------------------------------------------------

UNREACHABLE_OPS = {
    # LLM model/provider catalogue — no matching permission group (live-verified 8.0.0).
    ("get", "/ai/llm/model"),
    ("get", "/ai/llm/model/{model_id}"),
    ("get", "/ai/llm/provider"),
    ("get", "/ai/llm/provider/{provider_id}"),
    ("get", "/ai/llm/provider/model/{provider_id}"),
    # Agent config write — permission group is `agent/config` for POST only.
    ("put", "/ai/agent/config"),
    # Agent LLM config (POST) — 403 Access Denied on 8.0.0 (live-verified).
    ("post", "/ai/agent/llm/config"),
    # LLM config verify (POST form is unauthorised; GET form per-uuid is OK).
    ("post", "/ai/llm/config/verify"),
    # Agents alert triage (POST) — unauthorised despite appearing in service spec.
    ("post", "/ai/agents/alert"),
    # Triage task routes — the service re-mounts /ai/agents under /ai/triage,
    # but only `agents?/(.*)/trigger` is authorised.  The four task routes
    # under /ai/triage match nothing; POST /ai/triage/alert is authorised.
    ("post", "/ai/triage/{agent_name}/trigger"),
    ("post", "/ai/triage/{task_id}/acceptance"),
    ("get", "/ai/triage/{task_id}/result"),
    ("get", "/ai/triage/{task_id}/status"),
    # Insight POST returns 405 Method Not Allowed on 8.0.0 (live-verified).
    ("post", "/ai/insight/"),
}


# ---------------------------------------------------------------------------
# FastAPI summary overrides — the upstream OpenAPI ships auto-generated
# summaries that are wrong or misleading.  Keyed by (method, path).
# ---------------------------------------------------------------------------

SUMMARY_OVERRIDES = {
    ("get", "/ai/agent/"): {"summary": "List installed agents",
                              "description": "Returns all agents installed on this appliance, including their name, version, status (installed vs active), and inputformat contract for trigger payloads. Response: list of agent records with `id`, `uuid`, `name`, `version`, `status`."},
    ("post", "/ai/agent/activate"): {"summary": "Activate or deactivate an agent",
                               "description": "Activate or deactivate one or more agents by uuid. Accepts `uuids` (list of agent uuids) and `active` (boolean, default true). Must be installed before activation."},
    ("post", "/ai/agent/config"): {"summary": "Update agent configuration (LLM profile, MCP allowlist)",
                               "description": "Create or update an agent's LLM configuration profile, including which LLM provider and MCP servers the agent may call. Body requires `agent_name`, `agent_version`, and `config` object."},
    ("get", "/ai/agent/config/default"): {"summary": "Get default agent configuration template",
                               "description": "Return the system-wide agent configuration template (LLM provider, version, MCP allowlist) used for newly installed agents. Response: `AiAgentConfigurationDTO`."},
    ("post", "/ai/agent/config/default"): {"summary": "Update default agent configuration template",
                                           "description": "Update the system-wide agent configuration template. Affects all agents that use the default profile. Body: `config` object with LLM provider, model, and MCP server allowlist."},
    ("get", "/ai/agent/config/{agent_name}/{version}"): {"summary": "Get agent-specific configuration",
                                                       "description": "Return the configuration for a specific agent, including LLM provider, model version, and MCP server allowlist."},
    ("post", "/ai/agent/import"): {"summary": "Import an agent package (zip)",
                              "description": "Upload an agent package as multipart form (`file`). The agent lands inactive; call `POST /ai/agent/activate` with its uuid to make it eligible for routing. Set `?replace=true` to overwrite an existing agent of the same name+version."},
    ("post", "/ai/agent/export/{agent_id}"): {"summary": "Export an agent as a zip package",
                                       "description": "Download an installed agent as a zip archive. `agent_id` is the agent's uuid from `list_agents`."},
    ("delete", "/ai/agent/{name}/{version}"): {"summary": "Delete an installed agent",
                                           "description": "Delete an installed agent by name and version. The agent is removed from the appliance and its configuration is lost. Only admins can delete agents."},
    ("get", "/ai/agent/{name}/{version}"): {"summary": "Get agent details (including inputformat schema)",
                                          "description": "Return detailed information about a specific agent including its name, version, status, installed date, and inputformat schema (the expected structure for trigger data payloads)."},
    ("get", "/ai/agent/{uuid}"): {"summary": "Get agent by uuid",
                                "description": "Return agent information identified by its uuid. Returns the same agent record as returned by list_agents."},
    ("post", "/ai/agents/{agent_name}/trigger"): {"summary": "Trigger a single agent run",
                                        "description": "Trigger a single agent run. Returns a dict with `task_id` and `status` (`pending`). Poll with `GET /ai/agents/{task_id}/status` (returns one of `pending`, `inprogress`, `completed`, `failed`) and fetch results with `GET /ai/agents/{task_id}/result`."},
    ("get", "/ai/agents/{task_id}/status"): {"summary": "Get agent run status",
                                       "description": "Return current pipeline status for a triage task. While running: `pending` then `inprogress`; terminal: `completed` or `failed`."},
    ("get", "/ai/agents/{task_id}/result"): {"summary": "Get agent run result (answer, evidence, confidence)",
                                        "description": "Return the investigation result after the agent run completes. Contains `answer` (natural language), `evidence` (supporting data), and `confidence` score (0.0-1.0)."},
    ("post", "/ai/agents/{task_id}/acceptance"): {"summary": "Submit analyst feedback on agent result",
                                             "description": "Submit analyst acceptance/rejection feedback on the agent's result. Accepts a JSON object with `accepted` (boolean) and optional `reason` (string)."},
    ("get", "/ai/llm/config"): {"summary": "List LLM reasoning profiles",
                             "description": "Return all LLM reasoning profiles. Each profile defines the provider, model, temperature, and system prompt used by agents. Response: list of `LLMConfig` objects with `uuid`, `name`, `config`."},
    ("post", "/ai/llm/config"): {"summary": "Create an LLM reasoning profile",
                              "description": "Create one or more LLM reasoning profiles. Body: list of config objects, each with `name`, `provider`, `model`, and other provider-specific fields."},
    ("delete", "/ai/llm/config/{uuid}"): {"summary": "Delete an LLM reasoning profile",
                                        "description": "Delete the specified LLM reasoning profile by uuid. Agents using this profile will fall back to the default configuration."},
    ("get", "/ai/llm/config/{uuid}"): {"summary": "Get an LLM reasoning profile by uuid",
                                    "description": "Return the full LLM configuration record for the specified uuid, including provider, model name, temperature, system prompt, and active/default status."},
    ("get", "/ai/llm/config/{uuid}/verify"): {"summary": "Verify an LLM reasoning profile is callable",
                                         "description": "Test whether the specified LLM configuration can actually invoke a model (validates the provider endpoint, auth, and connectivity)."},
    ("get", "/ai/llm/allowed-providers"): {"summary": "List available LLM solution pack providers",
                                       "description": "Return the catalog of LLM providers bundled in the FortiSOAR solution pack (e.g., OpenAI, Azure OpenAI)."},
    ("get", "/ai/mcp"): {"summary": "List registered MCP servers",
                      "description": "Return all registered MCP servers that agents may call as tools during investigation. Response: list of `MCPServerRef` objects with `id`, `name`, `url`."},
    ("post", "/ai/mcp/validate"): {"summary": "Validate an MCP server configuration (handshake + auth)",
                               "description": "Validate an MCP server by attempting handshake and auth. Accepts `MCPServerConfig` body with `uuid`, `name`, `url`, and auth credentials. Returns `MCPValidateResult`."},
    ("post", "/ai/prompt/validate"): {"summary": "Validate a prompt template",
                                   "description": "Validate a prompt template string for Jinja2 interpolation errors. Returns a JSON object with `valid` (boolean) and `message` (string)."},
    ("post", "/ai/triage/alert"): {"summary": "Start an AI investigation for an alert",
                               "description": "Submit an alert for AI triage/investigation. Returns 202 Accepted with a JSON object containing `task_id` and `status` (`pending`). The task_id links to the investigation; use `get_status`/`get_result` to poll. If a record reference (e.g. `alerts:<uuid>`) is passed, the uuid is extracted and written back to the alert's `triagetaskid` field for later recovery."},
    ("post", "/ai/chat/"): {"summary": "Start or continue a conversational investigation",
                         "description": "Start or continue a conversational investigation session. Requires `user_id` and `message` in the request body. Returns a ChatResponse with response text and optional tool calls."},
    # Insight paths
    ("get", "/ai/insight/"): {"summary": "List scheduled insights",
                           "description": "Return all scheduled insights. Each insight has an `insight_id`, schedule, associated playbook, and last-run status."},
    ("get", "/ai/insight/{insight_id}"): {"summary": "Get scheduled insight details",
                                        "description": "Return details for a scheduled insight including its configuration, associated playbook, and last-run status."},
    ("delete", "/ai/insight/{insight_id}"): {"summary": "Delete a scheduled insight",
                                           "description": "Delete a previously-scheduled insight. The insight will stop running on its schedule."},
    ("post", "/ai/insight/chain_of_thoughts"): {"summary": "Generate a single-shot reasoning trace",
                                            "description": "Generate a single-shot chain-of-thought reasoning trace for an investigation. Requires LLM configuration and investigation context in the body."},
    ("post", "/ai/insight/plan"): {"summary": "Generate a multi-step investigation plan",
                               "description": "Generate a structured, multi-step investigation plan. Requires investigation context and optional constraints in the body. Returns a plan object with ordered steps."},
    ("post", "/ai/insight/plan/execute"): {"summary": "Execute an investigation plan asynchronously",
                                       "description": "Execute a previously-generated investigation plan. The plan runs asynchronously; poll with `GET /ai/insight/plan/{task_id}/status`."},
    ("get", "/ai/insight/plan/{task_id}/status"): {"summary": "Get plan execution status",
                                                "description": "Return the current status of an asynchronously-executing investigation plan. Returns `pending`, `inprogress`, `completed`, or `failed`."},
    ("get", "/ai/insight/plan/{task_id}/result"): {"summary": "Get plan execution result",
                                                "description": "Return the result of a completed investigation plan execution. Contains the plan output, evidence gathered, and analyst recommendations."},
    ("post", "/ai/insight/trigger/schedule"): {"summary": "Create or update a scheduled insight",
                                           "description": "Create or update a scheduled insight that runs at specified intervals. Requires playbook reference and schedule configuration in the body."},
    # Enrichment paths
    ("post", "/ai/enrich/context"): {"summary": "Retrieve knowledge-base enrichment for context",
                                  "description": "Retrieve vector-search enrichment from the knowledge base for a given context. Returns relevant indexed documents with similarity scores."},
    ("post", "/ai/enrich/context/index"): {"summary": "Index a document into the knowledge base",
                                       "description": "Embed and index a document into the knowledge-base vector store for later retrieval via RAG. Accepts a JSON body with `content` (string) and `metadata` (object)."},
    ("delete", "/ai/enrich/context/index/{uuid}"): {"summary": "Remove a document from the knowledge base index",
                                                 "description": "Delete a previously-indexed document from the knowledge-base vector store. The document will no longer be returned by RAG enrichment queries."},
    ("post", "/ai/enrich/index/build"): {"summary": "Build or rebuild the knowledge-base vector index",
                                      "description": "Rebuild (or create) the knowledge-base vector index from all indexed documents. Runs asynchronously; returns a task reference."},
    # MCP Admin paths (from mcp_server_openapi.json, summaries/descriptions may be empty)
    ("post", "/mcp/config/import"): {"summary": "Import exported MCP configuration",
                                   "description": "Import a previously-exported MCP server configuration. Reverses `POST /mcp/config/export`. Body: JSON payload from export."},
    ("put", "/mcp/tools/{mcp_config_uuid}"): {"summary": "Update tool allowlist for an MCP server",
                                            "description": "Update which tools a specific MCP server may expose. Body: tool names to enable or disable for the given server configuration uuid."},
    ("get", "/mcp/servers/{mcp_type}"): {"summary": "List available MCP tools for a server type",
                                       "description": "Return the list of available tools for a given MCP server type (e.g. `modules`, `playbooks`, `utility`). Each tool entry includes name, description, and input schema."},
}


# ---------------------------------------------------------------------------
# Pyfsr-only surfaces — paths pyfsr wraps that are absent from the AI service
# OpenAPI.  Hand-authored from pyfsr's typed wrappers and live captures.
# ---------------------------------------------------------------------------

PYFSR_ONLY_PATHS: dict[str, dict] = {}


def _ai_resp(desc, content_type="application/json"):
    return {"description": desc, "content": {content_type: {}}}


def _build_pyfsr_only_paths():
    """Populate PYFSR_ONLY_PATHS dict.  Separated into a function to keep global scope clean."""

    # --- /api/3/mcp_configurations — CRUD module (pyfsr-only) ---------------
    PYFSR_ONLY_PATHS["/api/3/mcp_configurations"] = {
        "get": {
            "tags": ["MCP Configurations"],
            "summary": "List registered MCP server configurations",
            "description": (
                "Returns full MCP server records including URL, auth type, and status. "
                "This is the authoritative CRUD store — the AI service only *reads and "
                "validates* registered servers via `/ai/mcp`. Use `?$limit`, `?$page` for pagination."
            ),
            "x-fsr-version": "8.0+",
            "responses": {"200": _ai_resp("Hydra paged collection of MCP server configurations.")},
        },
        "post": {
            "tags": ["MCP Configurations"],
            "summary": "Register a new MCP server configuration",
            "description": (
                "Persist an MCP server after validating it with `POST /ai/mcp/validate`. "
                "The body carries the server name, URL, auth type, and credentials. "
                "Typical flow: validate → POST. pyfsr wraps this as "
                "`client.ai.register_mcp_server()` and the convenience "
                "`client.ai.save_mcp_server()` (validate-then-persist)."
            ),
            "x-fsr-version": "8.0+",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"201": _ai_resp("Created."), "400": {"description": "Invalid configuration."}},
        },
    }

    PYFSR_ONLY_PATHS["/api/3/mcp_configurations/{uuid}"] = {
        "parameters": [
            {"name": "uuid", "in": "path", "required": True,
             "schema": {"type": "string", "format": "uuid"},
             "description": "MCP configuration uuid."}
        ],
        "get": {
            "tags": ["MCP Configurations"],
            "summary": "Get an MCP server configuration by uuid",
            "description": "Return the full MCP server configuration record for the specified uuid, including server URL, name, auth settings, and status.",
            "x-fsr-version": "8.0+",
            "responses": {"200": _ai_resp("MCP server configuration."), "404": {"description": "Not found."}},
        },
        "put": {
            "tags": ["MCP Configurations"],
            "summary": "Update an MCP server configuration",
            "description": "Update the MCP server configuration. Body carries the updated fields (name, URL, auth type, credentials). Only the specified fields are updated.",
            "x-fsr-version": "8.0+",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _ai_resp("Updated."), "404": {"description": "Not found."}},
        },
        "delete": {
            "tags": ["MCP Configurations"],
            "summary": "Delete an MCP server configuration",
            "description": "Delete the specified MCP server configuration. The server will no longer be available for agent tool calls.",
            "x-fsr-version": "8.0+",
            "responses": {"204": {"description": "Deleted."}, "404": {"description": "Not found."}},
        },
    }

    # --- /mcp/servers/connector — appliance MCP gateway (pyfsr-only) --------
    PYFSR_ONLY_PATHS["/mcp/servers/connector"] = {
        "get": {
            "tags": ["MCP Gateway"],
            "summary": "List connectors eligible for MCP tool hosting",
            "description": (
                "Returns which installed connectors can be hosted as MCP tool servers. "
                "pyfsr: `client.ai.mcp_connector_candidates()`."
            ),
            "x-fsr-version": "8.0+",
            "responses": {"200": _ai_resp("Array of connector candidates.")},
        },
    }

    PYFSR_ONLY_PATHS["/mcp/config/export"] = {
        "post": {
            "tags": ["MCP Gateway"],
            "summary": "Export current MCP tool catalog",
            "description": (
                "Export the live MCP tool list in a machine-readable format. "
                "Useful for IaC and drift detection. pyfsr: "
                "`client.ai.export_mcp_server_tools()`."
            ),
            "x-fsr-version": "8.0+",
            "responses": {"200": _ai_resp("Exported tool catalog.")},
        },
    }

    PYFSR_ONLY_PATHS["/mcp/add/tools"] = {
        "post": {
            "tags": ["MCP Gateway"],
            "summary": "Host an installed connector as an MCP server",
            "description": (
                "Binds a connector's operations as MCP tools on the appliance's MCP gateway. "
                "After calling this, the connector is available at "
                "`/mcp/connector/{connector_name}/`. pyfsr: "
                "`client.ai.host_connector_as_mcp_server()`."
            ),
            "x-fsr-version": "8.0+",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _ai_resp("Tools registered."), "400": {"description": "Connector not found or no tools."}},
        },
    }

    PYFSR_ONLY_PATHS["/mcp/tools/{uuid}"] = {
        "parameters": [
            {"name": "uuid", "in": "path", "required": True,
             "schema": {"type": "string"}, "description": "MCP tool uuid."}
        ],
        "put": {
            "tags": ["MCP Gateway"],
            "summary": "Update exposed tools for a connector's MCP server",
            "description": (
                "Change which tools a connector exposes over the MCP gateway. "
                "pyfsr: `client.ai.update_connector_mcp_server_tools()`."
            ),
            "x-fsr-version": "8.0+",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _ai_resp("Tools updated.")},
        },
    }

    PYFSR_ONLY_PATHS["/mcp/tools/delete"] = {
        "delete": {
            "tags": ["MCP Gateway"],
            "summary": "Delete specific MCP tools",
            "description": (
                "Remove tools from the MCP gateway. pyfsr: `client.ai.delete_mcp_tools()`."
            ),
            "x-fsr-version": "8.0+",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _ai_resp("Tools deleted.")},
        },
    }

    # --- /api/3/llm_activity_logs — audit module (pyfsr-only) ---------------
    PYFSR_ONLY_PATHS["/api/3/llm_activity_logs"] = {
        "get": {
            "tags": ["AI Activity"],
            "summary": "List LLM activity logs (tool-usage evidence)",
            "description": (
                "Returns tool-call evidence from agent investigations — the raw data behind "
                "a verdict. Filter by `task_id`, time range, or module. "
                "pyfsr: `client.ai.tool_usage()` for direct access, "
                "`client.ai.find_investigations(alert)` for alert-scoped lookup, "
                "`client.ai.investigation_tool_calls(task_id)` for task-scoped access."
            ),
            "x-fsr-version": "8.0+",
            "responses": {"200": _ai_resp("Array of LLM activity log records.")},
        },
    }


_build_pyfsr_only_paths()


# ---------------------------------------------------------------------------
# fsr-ai tag mapping — upstream uses one FastAPI tag per router; we regroup
# by prefix so the surface reads cleanly in the rendered docs.
# ---------------------------------------------------------------------------

AI_TAG_FOR_PREFIX = [
    ("/ai/insight",  "AI Insight"),
    ("/ai/agents",   "AI Agents"),
    ("/ai/triage",   "AI Agents"),   # /ai/triage is a re-mount of /ai/agents
    ("/ai/agent",    "AI Agents"),
    ("/ai/chat",     "AI Chat"),
    ("/ai/llm",      "AI LLM"),
    ("/ai/enrich",   "AI Enrichment"),
    ("/ai/mcp",      "AI MCP Registry"),
    ("/ai/prompt",   "AI Prompts"),
]


def _ai_tag(path: str) -> str:
    for prefix, tag in AI_TAG_FOR_PREFIX:
        if path == prefix or path.startswith(prefix + "/"):
            return tag
    return "AI Insight"  # only `/` left, harmless fallback


# ---------------------------------------------------------------------------
# Tag descriptions added to the curated SPEC when merge is enabled.
# ---------------------------------------------------------------------------

AI_MCP_TAG_DESCRIPTIONS = {
    "AI Insight": (
        "Generate and execute multi-step investigation plans. The classic flow is "
        "`POST /ai/insight/plan` → `POST /ai/insight/plan/execute` → poll "
        "`GET /ai/insight/plan/{task_id}/status` → `GET /ai/insight/plan/{task_id}/result`. "
        "Lower-level: `POST /ai/insight/chain_of_thoughts` returns a single-shot reasoning trace."
    ),
    "AI Agents": (
        "Agent execution + management. `POST /ai/agents/{agent_name}/trigger` "
        "and `POST /ai/triage/alert` kick off an agent run; "
        "`/ai/agents/{task_id}/{status,result,acceptance}` track it. "
        "`/ai/agent/*` (singular) is the agent **catalog** — import, export, "
        "activate, configure.\n\n"
        "**The `/ai/triage` vs `/ai/agents` trap:** the AI service mounts one "
        "router under both prefixes, so the raw service OpenAPI lists both as "
        "equals, but the front-door proxy only authorises "
        "`^agents?/(.*)/trigger` (the generic trigger) and "
        "`POST /ai/triage/alert` specifically.  The four `/ai/triage/{task_id}/*` "
        "routes return 403.  Always use `/ai/agents/` for status, result, and "
        "acceptance — never `/ai/triage/` for those."
    ),
    "AI Chat": "Conversational investigation. `POST /ai/chat/` starts or continues a thread.",
    "AI LLM": (
        "LLM provider, model, and per-tenant config catalog. Provider rows ship empty; "
        "the operator wires an OpenAI/local model with `POST /ai/llm/config` and verifies "
        "with `GET /ai/llm/config/{uuid}/verify`.  `GET /ai/llm/allowed-providers` "
        "lists available solution packs.\n\n"
        "**Note:** The LLM model and provider catalogue endpoints "
        "(`GET /ai/llm/model`, `GET /ai/llm/provider`) are exposed by the AI "
        "service but return 403 through the front-door proxy — no matching "
        "permission group exists.  They are omitted from this spec."
    ),
    "AI Enrichment": (
        "Knowledge-base ingestion for the agentic RAG store. `POST /ai/enrich/context` "
        "retrieves enrichment, `POST /ai/enrich/context/index` indexes a doc, "
        "`POST /ai/enrich/index/build` (re)builds the vector index."
    ),
    "AI Prompts": "Prompt template validation. `POST /ai/prompt/validate` lints a template.",
    "AI MCP Registry": (
        "Register external MCP servers that the AI agents may call. "
        "`GET /ai/mcp` lists them, `POST /ai/mcp/validate` round-trips a config "
        "(handshake + auth) before persisting."
    ),
    "MCP Admin": (
        "Tool catalog CRUD on the on-appliance MCP server. `POST /mcp/add/tools` "
        "binds an installed connector's operations as MCP tools; "
        "`POST /mcp/config/{import,export}` ships tool catalogs between appliances; "
        "`GET /mcp/servers/{mcp_type}?restricted=true` returns the live registry "
        "plus the hard-coded restricted list."
    ),
    "MCP Tools": (
        "The four streamable-HTTP MCP endpoints. These speak JSON-RPC, not REST, "
        "so they are not in the upstream OpenAPI. The operations below document "
        "the wire shape and list the tools each surface exposes on a stock "
        "appliance. Hit them with `Accept: application/json, text/event-stream`, "
        "run `initialize` first, capture the `mcp-session-id` response header, "
        "and reuse it on every subsequent call."
    ),
    "MCP Configurations": (
        "Full CRUD store for registered MCP servers. This is where servers are "
        "actually created (`/api/3/mcp_configurations`). The AI service only reads "
        "and validates them via `/ai/mcp`. Keep these tags distinct — conflating "
        "MCP Configurations with AI MCP Registry is the most common source of confusion."
    ),
    "MCP Gateway": (
        "Appliance MCP gateway for tool hosting. Manage which connectors are exposed "
        "as MCP tools, export tool catalogs, and update tool permissions."
    ),
    "AI Activity": (
        "LLM activity audit logs. Tool-call evidence from agent investigations, "
        "useful for understanding what an agent did to reach its verdict."
    ),
}


AI_MCP_TAG_GROUPS = [
    {
        "name": "AI (8.0+)",
        "tags": [
            "AI Insight",
            "AI Agents",
            "AI Chat",
            "AI LLM",
            "AI Enrichment",
            "AI Prompts",
            "AI MCP Registry",
            "AI Activity",
        ],
    },
    {
        "name": "MCP (8.0+)",
        "tags": ["MCP Admin", "MCP Configurations", "MCP Gateway", "MCP Tools"],
    },
]


# ---------------------------------------------------------------------------
# MCP streamable-HTTP synthesized operations
# ---------------------------------------------------------------------------

MCP_PROTOCOL_DESC = """\
**MCP streamable-HTTP endpoint** (JSON-RPC 2.0 over HTTP + SSE).

Required headers on every call:

```
Authorization: Bearer <jwt>         # or API-KEY <key>, or CS <hmac> (+ Forwarded-Authorization)
Content-Type: application/json
Accept: application/json, text/event-stream
```

Wire flow:

1. `POST` an `initialize` JSON-RPC envelope. Response is `200 OK` SSE; capture the
   `mcp-session-id` response header.
2. `POST` a `notifications/initialized` envelope (no `id`) with the session header.
3. `POST` `tools/list`, `tools/call`, `prompts/list`, etc. — every call must carry
   `mcp-session-id`.

The request/response schemas below are MCP-protocol envelopes, not endpoint-specific.
"""


def _mcp_protocol_op(tag: str, summary: str, tool_names: list[str], tools_json: list[dict]) -> dict:
    tool_lines = []
    by_name = {t["name"]: t for t in tools_json}
    for name in tool_names:
        t = by_name.get(name, {})
        title = t.get("title") or name
        desc = (t.get("description") or "").splitlines()[0]
        req = t.get("inputSchema", {}).get("required", []) or []
        req_s = ", ".join(req) if req else "—"
        tool_lines.append(f"- `{name}` ({title}) — required: {req_s}. {desc}".rstrip())
    desc = MCP_PROTOCOL_DESC + "\n**Tools exposed on a stock 8.0 appliance:**\n\n" + "\n".join(tool_lines)
    return {
        "summary": summary,
        "description": desc,
        "tags": [tag],
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/McpJsonRpcRequest"},
                    "examples": {
                        "initialize": {
                            "summary": "Open a session",
                            "value": {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2025-03-26",
                                    "capabilities": {},
                                    "clientInfo": {"name": "example", "version": "0.1"},
                                },
                            },
                        },
                        "tools_list": {
                            "summary": "List tools (after initialize)",
                            "value": {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                        },
                    },
                }
            },
        },
        "responses": {
            "200": {
                "description": "JSON-RPC response, framed as an SSE `event: message` line.",
                "content": {
                    "text/event-stream": {
                        "schema": {"$ref": "#/components/schemas/McpJsonRpcResponse"}
                    }
                },
                "headers": {
                    "mcp-session-id": {
                        "schema": {"type": "string"},
                        "description": "Returned on `initialize`; required on every subsequent call.",
                    }
                },
            },
            "406": {
                "description": "Missing `Accept: text/event-stream`.",
            },
        },
    }


# ---------------------------------------------------------------------------
# Schemas added when the merge runs (minimal — full tool inputSchemas live
# in the MCP tool dump for now; we surface only the protocol envelope).
# ---------------------------------------------------------------------------

EXTRA_SCHEMAS = {
    "McpJsonRpcRequest": {
        "type": "object",
        "required": ["jsonrpc", "method"],
        "properties": {
            "jsonrpc": {"type": "string", "enum": ["2.0"]},
            "id": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
            "method": {"type": "string", "example": "tools/list"},
            "params": {"type": "object"},
        },
    },
    "McpJsonRpcResponse": {
        "type": "object",
        "required": ["jsonrpc"],
        "properties": {
            "jsonrpc": {"type": "string", "enum": ["2.0"]},
            "id": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
            "result": {"type": "object"},
            "error": {
                "type": "object",
                "properties": {
                    "code": {"type": "integer"},
                    "message": {"type": "string"},
                    "data": {},
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Merge entry point
# ---------------------------------------------------------------------------

def merge_ai_mcp(spec: dict[str, Any]) -> int:
    """Mutate `spec` in place. Returns the count of paths added."""
    recon = _recon_dir()
    fsr_ai = json.loads((recon / "fsr_ai_openapi.json").read_text())
    mcp_admin = json.loads((recon / "mcp_server_openapi.json").read_text())
    tools_payload = json.loads((recon / "mcp_tools_live.json").read_text())

    added = 0
    filtered = 0
    ops: list[tuple[str, str]] = []  # (method, path) tuples for pyfsr samples

    # ---- 1. fsr-ai paths (with reachability filter) -----------------------
    for path, methods in fsr_ai.get("paths", {}).items():
        if path == "/":  # uvicorn welcome root, not useful in curated docs
            continue
        tag = _ai_tag(path)
        new_methods = {}
        for method, op in methods.items():
            if method not in {"get", "post", "put", "delete", "patch"}:
                new_methods[method] = op
                continue
            # Fix: /ai/llm/config/{uuid}/verify is missing the `uuid` path param
            # in the service OpenAPI.  Patch it in.
            if path == "/ai/llm/config/{uuid}/verify" and method == "get":
                op.setdefault("parameters", [])
                op["parameters"].append({
                    "name": "uuid",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "uuid of the LLM reasoning profile.",
                })

            # Reachability filter — drop ops the PHP proxy rejects.
            if (method, path) in UNREACHABLE_OPS:
                filtered += 1
                continue
            op = dict(op)
            op["tags"] = [tag]
            op["x-fsr-version"] = "8.0+"
            if tag in {"AI Insight", "AI Chat", "AI Agents"}:
                op["x-fsr-status"] = "requires-llm-config"
            # Apply summary overrides where the FastAPI auto-summary is wrong.
            override = SUMMARY_OVERRIDES.get((method, path))
            if override:
                op.update(override)
            new_methods[method] = op
            ops.append((method, path))
        if new_methods:
            spec["paths"][path] = new_methods
            added += 1
        else:
            # Path existed but all methods filtered — still count it
            added += 1

    # ---- 2. mcp-server REST admin -----------------------------------------
    for path, methods in mcp_admin.get("paths", {}).items():
        new_methods = {}
        for method, op in methods.items():
            if method not in {"get", "post", "put", "delete", "patch"}:
                new_methods[method] = op
                continue
            op = dict(op)
            op["tags"] = ["MCP Admin"]
            op["x-fsr-version"] = "8.0+"
            # Apply summary overrides where the mcp-server OpenAPI is terse.
            override = SUMMARY_OVERRIDES.get((method, path))
            if override:
                op.update(override)
            new_methods[method] = op
            ops.append((method, path))
        spec["paths"][path] = new_methods
        added += 1

    # ---- 3. MCP protocol endpoints ----------------------------------------
    family_to_tools = {
        "modules":   ("module", "List/fetch FortiSOAR module records as MCP tools."),
        "playbooks": ("playbooks", "Trigger playbooks (generic + dynamically-registered) as MCP tools."),
        "utility":   ("utility", "Helper MCP tools (current time, etc.)."),
    }
    for url_seg, (tools_key, summary) in family_to_tools.items():
        tool_names = [t["name"] for t in tools_payload.get(tools_key, [])]
        path = f"/mcp/{url_seg}/"
        spec["paths"][path] = {
            "post": _mcp_protocol_op(
                tag="MCP Tools",
                summary=summary,
                tool_names=tool_names,
                tools_json=tools_payload.get(tools_key, []),
            ),
            "parameters": [],
        }
        added += 1
        ops.append(("post", path))

    # Connector gateway — dynamic per-connector mount.
    spec["paths"]["/mcp/connector/{connector_name}/"] = {
        "post": _mcp_protocol_op(
            tag="MCP Tools",
            summary="Per-connector MCP gateway. One sub-app per installed connector.",
            tool_names=[],
            tools_json=[],
        ) | {"parameters": [
            {
                "name": "connector_name",
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": "Connector slug as registered via `POST /mcp/add/tools`.",
            }
        ]},
    }
    added += 1
    ops.append(("post", "/mcp/connector/{connector_name}/"))

    # ---- 4. Pyfsr-only surfaces -------------------------------------------
    for path, path_ops in PYFSR_ONLY_PATHS.items():
        spec["paths"][path] = path_ops
        added += 1
        for m in path_ops:
            if m in {"get", "post", "put", "delete", "patch"}:
                ops.append((m, path))


    # ---- 5. Tag groups + descriptions -------------------------------------
    existing_tag_names = {t["name"] for t in spec.get("tags", [])}
    for name, desc in AI_MCP_TAG_DESCRIPTIONS.items():
        if name not in existing_tag_names:
            spec.setdefault("tags", []).append({"name": name, "description": desc})
    spec.setdefault("x-tagGroups", []).extend(AI_MCP_TAG_GROUPS)

    # ---- 6. Components schemas --------------------------------------------
    spec.setdefault("components", {}).setdefault("schemas", {}).update(EXTRA_SCHEMAS)

    # Merge mcp-server's own component schemas so $ref'd request bodies resolve.
    for k, v in (mcp_admin.get("components", {}).get("schemas") or {}).items():
        spec["components"]["schemas"].setdefault(k, v)
    for k, v in (fsr_ai.get("components", {}).get("schemas") or {}).items():
        spec["components"]["schemas"].setdefault(k, v)

    print(f"  [AI/MCP] filtered {filtered} unreachable ops (front-door proxy 403)")
    return added, ops
