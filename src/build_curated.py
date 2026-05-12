"""Build a curated FortiSOAR OpenAPI 3.1 spec from markdown sources.

Sources (authoritative, in this order):
  1. fortisoar-api-docs/FortiSOAR-API-Guide.md     (public PDF -> markdown)
  2. soar-reporting-dashboard-cl/docs/FORTISOAR_API.md
  3. FSRPlaybookYaml/store/QUERY_API.md + WF_DJANGO_API.md

This is intentionally hand-shaped (NOT generated from Insomnia/Hydra) so
every operation, parameter, and schema field is something a human picked
because it matters. Coverage is the curated core surface; queue
expansions in TODOS.md.

Outputs build/fortisoar.curated.openapi.yaml.
The companion src/verify_curated.py exercises every op against a live
FSR (creds in .env) and emits build/curated_verification.json which the
Scalar page surfaces as per-op verified badges.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "fortisoar.curated.openapi.yaml"


# ---------------------------------------------------------------------------
# Reusable schema fragments
# ---------------------------------------------------------------------------

SCHEMAS = {
    "IRI": {
        "type": "string",
        "description": "Internationalized Resource Identifier - relative URL pointing to a record. Example: /api/3/alerts/028b37fa-bb35-4e3b-8afb-a3274a8cb343.",
        "example": "/api/3/alerts/028b37fa-bb35-4e3b-8afb-a3274a8cb343",
    },
    "UUID": {
        "type": "string",
        "format": "uuid",
        "example": "028b37fa-bb35-4e3b-8afb-a3274a8cb343",
    },
    "EpochMs": {
        "type": "integer",
        "format": "int64",
        "description": "Milliseconds since Unix epoch (UTC).",
    },
    "HydraCollection": {
        "type": "object",
        "description": "Standard Hydra paged collection wrapper. `hydra:member` is the array of records; the rest is navigation/pagination metadata.",
        "properties": {
            "@context": {"type": "string", "example": "/api/3/contexts/Alert"},
            "@id": {"type": "string", "example": "/api/3/alerts"},
            "@type": {"type": "string", "example": "hydra:PagedCollection"},
            "hydra:totalItems": {"type": "integer", "example": 1},
            "hydra:itemsPerPage": {"type": "integer", "example": 30},
            "hydra:nextPage": {"type": "string", "example": "/api/3/alerts?%24page=2"},
            "hydra:firstPage": {"type": "string"},
            "hydra:lastPage": {"type": "string"},
            "hydra:member": {
                "type": "array",
                "items": {"type": "object"},
            },
            "hydra:search": {
                "type": "object",
                "properties": {
                    "@type": {"type": "string", "example": "hydra:IriTemplate"},
                    "hydra:template": {"type": "string"},
                    "hydra:variableRepresentation": {"type": "string"},
                    "hydra:mapping": {"type": "array", "items": {"type": "object"}},
                },
            },
        },
        "required": ["@context", "@id", "@type", "hydra:member"],
    },
    "QueryBody": {
        "type": "object",
        "description": "Body shape for `POST /api/query/{collection}`. Logic groups, leaf filters, sort, and aggregates - see the Query reference in the introduction for full operator semantics.",
        "properties": {
            "logic": {
                "type": "string",
                "enum": ["AND", "OR"],
                "description": "Top-level logical join. Nest by giving a child filter its own `logic` field.",
            },
            "filters": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {
                            "type": "object",
                            "description": "Leaf filter.",
                            "properties": {
                                "field": {"type": "string", "example": "severity.itemValue"},
                                "operator": {
                                    "type": "string",
                                    "enum": [
                                        "eq", "neq", "lt", "lte", "gt", "gte",
                                        "in", "nin", "like", "notlike",
                                        "contains", "exists", "isnull",
                                    ],
                                    "default": "eq",
                                },
                                "value": {},
                                "type": {"type": "string", "description": "Optional explicit type hint (datetime, integer, ...)."},
                            },
                            "required": ["field"],
                        },
                        {
                            "type": "object",
                            "description": "Nested group - recurse with its own logic + filters.",
                            "properties": {
                                "logic": {"type": "string", "enum": ["AND", "OR"]},
                                "filters": {"type": "array"},
                            },
                            "required": ["logic", "filters"],
                        },
                    ],
                },
            },
            "sort": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "field": {"type": "string"},
                        "direction": {"type": "string", "enum": ["asc", "desc", "ASC", "DESC"]},
                    },
                    "required": ["field", "direction"],
                },
            },
            "aggregates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "operator": {
                            "type": "string",
                            "enum": [
                                "fields", "select", "count", "countdistinct",
                                "groupby", "distinct", "sum", "max", "min",
                                "avg", "median",
                            ],
                        },
                        "field": {"type": "string"},
                        "alias": {"type": "string"},
                    },
                    "required": ["operator", "field"],
                },
                "description": "Presence of any operator other than `fields`/`select` flips the response into aggregate mode (rows of aggregate values instead of records).",
            },
            "__selectFields": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Allowlist of fields to return on each `hydra:member` record. "
                    "Reduces response size when you only need a subset. "
                    "Mutually exclusive with `__ignoreFields` (use one or the other). "
                    "Lighter alternative to `aggregates: [{operator: fields, ...}]` - "
                    "doesn't switch the query into aggregate mode."
                ),
                "example": ["id", "uuid", "name", "severity", "status"],
            },
            "__ignoreFields": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Denylist of fields to strip from each `hydra:member` record. "
                    "Useful when exporting records and you want to drop ownership / "
                    "audit fields (`createDate`, `createUser`, `modifyDate`, `modifyUser`)."
                ),
                "example": ["createDate", "createUser", "modifyDate", "modifyUser"],
            },
        },
    },
    "Alert": {
        "type": "object",
        "description": "An Alert record. Field set is illustrative - 127 properties exist on this entity per the Hydra walk; the ones below are the most-used. Full list via GET /api/3/contexts/Alert.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Alert"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": "string", "example": "Malicious Attachment - Malware.Binary.Vbs"},
            "sourceId": {"type": ["string", "null"]},
            "source": {"type": ["string", "null"], "example": "FireEye EX - Email MPS"},
            "description": {"type": ["string", "null"]},
            "type": {"type": ["string", "null"], "description": "IRI to picklist value, e.g. /api/3/picklists/<uuid>."},
            "severity": {"type": ["string", "null"], "description": "IRI to AlertSeverity picklist value."},
            "status": {"type": ["string", "null"], "description": "IRI to AlertStatus picklist value."},
            "assignedTo": {"type": ["string", "null"], "description": "IRI to /api/3/people/<uuid>."},
            "dueDate": {"type": ["integer", "null"], "format": "int64"},
            "createUser": {"type": ["object", "string", "null"]},
            "modifyUser": {"type": ["string", "null"]},
            "createDate": {"type": ["integer", "null"], "format": "int64"},
            "modifyDate": {"type": ["integer", "null"], "format": "int64"},
            "id": {"type": "integer"},
        },
    },
    "RecordLog": {
        "type": "object",
        "description": "One audit event record returned by `POST /api/gateway/audit/activities`.",
        "properties": {
            "id": {"type": "integer"},
            "transactionDate": {"$ref": "#/components/schemas/EpochMs"},
            "component": {
                "type": "string",
                "enum": ["das", "crudhub", "sealab", "agent", "sdk"],
            },
            "subComponent": {"type": "string"},
            "operation": {"$ref": "#/components/schemas/AuditOperation"},
            "user": {"type": "string", "description": "Display name."},
            "userId": {"type": "string", "description": "Login id."},
            "source": {"type": "string", "description": "Source IP."},
            "entityUuid": {"$ref": "#/components/schemas/UUID"},
            "entityType": {"type": "string", "example": "alerts"},
            "entitySingularName": {"type": "string"},
            "title": {"type": "string"},
            "displayName": {"type": "string", "description": "Often dirty - extra whitespace / embedded UUIDs / unrelated text. Sanitize client-side."},
            "playbookIri": {"type": ["string", "null"]},
            "playbookName": {"type": ["string", "null"]},
            "data": {"type": "object"},
            "rawData": {"type": "object"},
            "linkEntityDetails": {"type": "object"},
            "teamIris": {"type": "array", "items": {"$ref": "#/components/schemas/IRI"}},
            "userOwnerIris": {"type": "array", "items": {"$ref": "#/components/schemas/IRI"}},
            "legacy": {"type": "boolean"},
        },
    },
    "AuditOperation": {
        "type": "string",
        "description": "One of 45 valid operation values (per GET /api/gateway/audit/operations on FSR 7.6.5).",
        "enum": [
            "Create", "Update", "Delete", "Bulk Delete", "Bulk Insert", "Soft Delete",
            "Archival Start", "Archival Failure", "Restore", "Link", "Unlink",
            "Import", "Update During Import", "Overwrite During Import",
            "Comment", "Event", "Trigger", "Resume", "Retry", "Terminate",
            "Version Created", "Version Deleted",
            "Login Success", "Login Failed", "Log Out",
            "Install", "Uninstall", "Upgrade",
            "AddConfig", "DeleteConfig", "UpdateConfig",
            "Executed Action", "Activate", "Deactivate", "Validate",
            "Replication Failed", "Publish", "Clone", "Revert", "Collect",
            "Start", "Stop",
            "Pre-Processing(Drop)", "Pre-Processing(Update)", "Pre-Processing(Fail)",
        ],
    },
    "Error": {
        "type": "object",
        "description": "Hydra error envelope returned by FortiSOAR on validation / lookup / permission failures.",
        "properties": {
            "@context": {"type": "string", "example": "/api/3/contexts/Error"},
            "@type": {"type": "string", "example": "Error"},
            "hydra:title": {"type": "string"},
            "hydra:description": {"type": "string"},
        },
    },
    "AuthRequest": {
        "type": "object",
        "required": ["credentials"],
        "properties": {
            "credentials": {
                "type": "object",
                "required": ["loginid", "password"],
                "properties": {
                    "loginid": {"type": "string", "example": "csadmin"},
                    "password": {"type": "string", "format": "password"},
                },
            },
        },
    },
    "AuthResponse": {
        "type": "object",
        "properties": {
            "token": {
                "type": "string",
                "description": "JWT - pass as `Authorization: Bearer <token>` on subsequent requests. Default TTL ~30 min.",
            },
        },
    },
}


# Standard query parameters reused across /api/3/*
COMMON_QPARAMS = [
    {"name": "$limit", "in": "query", "description": "Max records per page. Default 30, max 5000.",
     "schema": {"type": "integer", "default": 30, "minimum": 1, "maximum": 5000}},
    {"name": "$page", "in": "query", "description": "1-indexed page number.",
     "schema": {"type": "integer", "default": 1, "minimum": 1}},
    {"name": "$orderby", "in": "query", "description": "Sort field; prefix `-` for descending. Example: `-createDate`.",
     "schema": {"type": "string", "example": "-createDate"}},
    {"name": "$relationships", "in": "query", "description": "Inline related records instead of returning IRI refs.",
     "schema": {"type": "boolean", "default": False}},
    {"name": "$export", "in": "query", "description": "Strip identity fields so the result re-imports cleanly.",
     "schema": {"type": "boolean", "default": False}},
    {"name": "$partial", "in": "query", "description": "Skip the COUNT(*) - omits hydra:totalItems for faster paging.",
     "schema": {"type": "boolean", "default": False}},
    {"name": "$search", "in": "query", "description": "Case-insensitive substring search across the entity's searchable fields. Tokenized when multi-word; AND-combinable with body filters; no min length.",
     "schema": {"type": "string"}},
    {"name": "$fields", "in": "query",
     "description": "Comma-separated projection - return only these columns. Big response-size win on bulk pulls. Example: `uuid,name,severity,status,createDate`.",
     "schema": {"type": "string"}},
]


# Common record-collection filter params. Documented as illustrative
# examples - the URL-param grammar accepts ANY field path with any
# operator, not just these. See the Query reference in the introduction.
RECORD_FILTER_QPARAMS = [
    {"name": "name", "in": "query",
     "description": "Exact-match filter on the record's name.",
     "schema": {"type": "string"}, "example": "Phishing email - finance"},
    {"name": "name$like", "in": "query",
     "description": "Case-insensitive LIKE filter on name. Use `%` and `_` wildcards.",
     "schema": {"type": "string"}, "example": "%phish%"},
    {"name": "severity.itemValue", "in": "query",
     "description": "Filter by the picklist value's display label (e.g. `High`, `Critical`).",
     "schema": {"type": "string"}, "example": "High"},
    {"name": "severity.itemValue$in", "in": "query",
     "description": "Multi-value filter, pipe-delimited.",
     "schema": {"type": "string"}, "example": "High|Critical"},
    {"name": "status.itemValue", "in": "query",
     "description": "Filter by status picklist label.",
     "schema": {"type": "string"}, "example": "Open"},
    {"name": "status.itemValue$neq", "in": "query",
     "description": "Exclude records with this status.",
     "schema": {"type": "string"}, "example": "Closed"},
    {"name": "assignedTo", "in": "query",
     "description": "Filter by assignee IRI (`/api/3/people/<uuid>`).",
     "schema": {"type": "string"}},
    {"name": "createDate$gte", "in": "query",
     "description": "Created on or after this epoch (seconds). Pair with `createDate$lte` for windows.",
     "schema": {"type": "integer", "format": "int64"}, "example": 1736380800},
    {"name": "createDate$lte", "in": "query",
     "description": "Created on or before this epoch (seconds).",
     "schema": {"type": "integer", "format": "int64"}},
    {"name": "modifyDate$gte", "in": "query",
     "description": "Modified on or after this epoch. Useful for incremental sync.",
     "schema": {"type": "integer", "format": "int64"}},
    {"name": "tags.itemValue", "in": "query",
     "description": "Filter by tag label.",
     "schema": {"type": "string"}},
]


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def _resp(desc, ref=None, example=None):
    content = {}
    if ref or example is not None:
        content = {"application/json": {}}
        if ref:
            content["application/json"]["schema"] = {"$ref": f"#/components/schemas/{ref}"}
        if example is not None:
            content["application/json"]["example"] = example
    out = {"description": desc}
    if content:
        out["content"] = content
    return out


def _err(code, desc):
    return {
        "description": desc,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
    }


PATHS = {}


# --- Authentication --------------------------------------------------------

PATHS["/auth/authenticate"] = {
    "post": {
        "tags": ["Authentication"],
        "summary": "Issue a JWT bearer token",
        "description": (
            "Token-based authentication. Returns a JWT for use as `Authorization: Bearer <token>` "
            "on subsequent requests. Default TTL is ~30 minutes; long-running clients should "
            "re-authenticate on 401.\n\n"
            "**Note:** The path is `/auth/authenticate` (no `/api` prefix). The PDF "
            "references `/api/auth/token` as the canonical endpoint, but on current builds "
            "it returns 403 even with a valid bearer; use this one."
        ),
        "security": [],
        "requestBody": {
            "required": True,
            "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/AuthRequest"},
                "example": {"credentials": {"loginid": "csadmin", "password": "<password>"}},
            }},
        },
        "responses": {
            "200": _resp("JWT issued.", ref="AuthResponse",
                         example={"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."}),
            "401": _err(401, "Invalid credentials."),
        },
    },
}

PATHS["/api/3/logout"] = {
    "post": {
        "tags": ["Authentication"],
        "summary": "Server-side session invalidation",
        "description": "Invalidates the bearer token server-side, complementing JWT expiry. Optional - JWTs expire on their own.",
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object"}, "example": {},
        }}},
        "responses": {"204": {"description": "Logged out."}},
    },
}

PATHS["/api/auth/cluster/health"] = {
    "get": {
        "tags": ["System"],
        "summary": "HA cluster health",
        "description": "Returns one object per cluster node with 17 fields (status, services, connectivity, cpu, memory, disk, replication_stat, workflow, ...).",
        "responses": {"200": _resp("Per-node health array.")},
    },
}

PATHS["/api/auth/license"] = {
    "get": {
        "tags": ["System"],
        "summary": "License information",
        "description": (
            "*Heads-up:* JWT-only on 7.6.x (API key returns 403). Some "
            "builds also return a generic 400 on the JWT path - the "
            "endpoint is wired through the auth standalone service and "
            "is sensitive to backend-side state. Skip if your monitoring "
            "doesn't strictly need it."
        ),
        "responses": {"200": _resp("License details.")},
    },
}

PATHS["/api/version"] = {
    "get": {
        "tags": ["System"],
        "summary": "Build version",
        "description": "**Public, no auth required.** Cheap unauthenticated probe.",
        "security": [],
        "responses": {"200": _resp("Version string.", example={"version": "7.6.5-5662"})},
    },
}

PATHS["/api/permissions/current"] = {
    "get": {
        "tags": ["Authentication"],
        "summary": "Current user's effective permissions",
        "description": "78-key map of module -> {create, read, update, delete, execute} booleans. Authoritative for UI gating.",
        "responses": {"200": _resp("Permission matrix.")},
    },
}

PATHS["/api/3/actors/current"] = {
    "get": {
        "tags": ["Authentication"],
        "summary": "Current actor (user or appliance)",
        "description": (
            "Returns the calling principal as a unified Actor record - either a user or an appliance/agent. "
            "Use this when code needs to work uniformly across both auth modes; for user-only fields, "
            "prefer `GET /api/3/people/current`."
        ),
        "responses": {"200": _resp("Actor record.")},
    },
}


# --- Records: generic + concrete (Alerts) ---------------------------------

def _record_path_ops(plural, schema_ref, *, tag, singular):
    """Emit the four module-root + module-record ops for a given collection."""
    return {
        f"/api/3/{plural}": {
            "get": {
                "tags": [tag],
                "summary": f"List {plural}",
                "description": (
                    f"Returns a Hydra paged collection of {plural}. "
                    f"Filter via `?<field>$<operator>=<value>` (URL-param grammar - see Query API). "
                    f"Reserved `$`-params apply: `$limit`, `$page`, `$orderby`, `$relationships`, `$search`."
                ),
                "parameters": COMMON_QPARAMS + RECORD_FILTER_QPARAMS,
                "responses": {
                    "200": {
                        "description": f"Hydra collection of {plural}.",
                        "content": {"application/json": {
                            "schema": {
                                "allOf": [
                                    {"$ref": "#/components/schemas/HydraCollection"},
                                    {"type": "object", "properties": {
                                        "hydra:member": {"type": "array", "items": {"$ref": f"#/components/schemas/{schema_ref}"}},
                                    }},
                                ],
                            },
                        }},
                    },
                    "401": _err(401, "Missing or invalid auth."),
                },
            },
            "post": {
                "tags": [tag],
                "summary": f"Create {singular}",
                "description": (
                    f"Inserts a new {singular} record. Picklist fields must be IRIs to existing "
                    f"`/api/3/picklists/<uuid>` values - bare strings are rejected from 7.5.0 onwards."
                ),
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {
                        "schema": {"$ref": f"#/components/schemas/{schema_ref}"},
                    }},
                },
                "responses": {
                    "201": _resp("Created.", ref=schema_ref),
                    "400": _err(400, "Validation error (e.g. invalid picklist value, missing required field)."),
                },
            },
        },
        f"/api/3/{plural}/{{uuid}}": {
            "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
            "get": {
                "tags": [tag],
                "summary": f"Get {singular} by uuid",
                "responses": {"200": _resp(f"{singular} record.", ref=schema_ref), "404": _err(404, "Not found.")},
            },
            "put": {
                "tags": [tag],
                "summary": f"Update {singular}",
                "description": "Full or partial update. The body must include `@id` matching the path.",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema_ref}"}}}},
                "responses": {"200": _resp("Updated.", ref=schema_ref)},
            },
            "delete": {
                "tags": [tag],
                "summary": f"Delete {singular}",
                "responses": {"204": {"description": "Deleted."}, "404": _err(404, "Not found.")},
            },
        },
    }


# Generic CRUD (templated)
PATHS.update(_record_path_ops("alerts", "Alert", tag="Alerts", singular="alert"))

# Generic templated record CRUD - documents the pattern
PATHS["/api/3/{collection}"] = {
    "parameters": [{"name": "collection", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Plural module name. Examples: alerts, incidents, indicators, tasks, people, workflows, connectors."}],
    "get": {
        "tags": ["Records (generic)"],
        "summary": "List records of any module",
        "description": (
            "Generic Hydra-paged listing for any module. Every record-bearing entity is auto-exposed at "
            "`/api/3/<plural>`; this template documents the shared contract.\n\n"
            "Common collections: `alerts`, `incidents`, `indicators`, `tasks`, `assets`, `people`, "
            "`appliances`, `workflows`, `playbooks`, `connectors`, `roles`, `teams`, `api_keys`, "
            "`comments`, `notes`, `attachments`, `picklists`, `picklist_names`, `model_metadatas`, "
            "`attribute_metadatas`, `dashboard`, `reporting`, `tenants`, `agents`, `routers`, "
            "`solutionpacks`, `widgets`, `workflow_collections`, `query_objects`, `import_jobs`, "
            "`export_jobs`, `preprocessing_rules`."
        ),
        "parameters": COMMON_QPARAMS,
        "responses": {"200": _resp("Hydra collection.", ref="HydraCollection")},
    },
    "post": {
        "tags": ["Records (generic)"],
        "summary": "Create a record in any module",
        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {"201": _resp("Created.")},
    },
}

PATHS["/api/3/{collection}/{uuid}"] = {
    "parameters": [
        {"name": "collection", "in": "path", "required": True, "schema": {"type": "string"}},
        {"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}},
    ],
    "get": {"tags": ["Records (generic)"], "summary": "Get a record",
            "responses": {"200": _resp("Record."), "404": _err(404, "Not found.")}},
    "put": {"tags": ["Records (generic)"], "summary": "Update a record",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _resp("Updated.")}},
    "delete": {"tags": ["Records (generic)"], "summary": "Delete a record",
               "responses": {"204": {"description": "Deleted."}}},
}


# --- Bulk record ops -------------------------------------------------------

for verb, op_method, op_summary, op_desc, body_shape in [
    ("insert",     "post",   "Bulk insert", "Insert multiple records of the given module type in one call.", "array_obj"),
    ("update",     "put",    "Bulk update", "Update multiple records (each with its `@id`). **Method is PUT**, not POST.", "array_obj"),
    ("delete",     "delete", "Bulk delete", "Delete multiple records by IRI list. **Method is DELETE**, not POST.", "array_str"),
    ("upsert",     "post",   "Upsert by natural key",
     "Insert-or-update **a single record** keyed on the module's identifier field. Body is a JSON object, "
     "not an array — use `/api/3/bulkupsert/{moduleType}` for the array variant.", "object"),
    ("bulkupsert", "post",   "Bulk upsert",
     "Array-input version of upsert. Body must be a JSON array; some 7.6.x builds return 500 (server-side "
     "TypeError) when given anything else.", "array_obj"),
]:
    op_def = {
        "tags": ["Bulk operations"],
        "summary": op_summary,
        "description": op_desc,
        "responses": {"200": _resp("Result envelope (per-record status).")},
    }
    if body_shape == "array_obj":
        schema = {"type": "array", "items": {"type": "object"}}
    elif body_shape == "array_str":
        schema = {"type": "array", "items": {"type": "string"}}
    else:  # object
        schema = {"type": "object"}
    op_def["requestBody"] = {"required": True, "content": {"application/json": {"schema": schema}}}
    PATHS[f"/api/3/{verb}/{{moduleType}}"] = {
        "parameters": [{"name": "moduleType", "in": "path", "required": True, "schema": {"type": "string"}, "example": "alerts"}],
        op_method: op_def,
    }

PATHS["/api/ingest-feeds/indicators"] = {
    "post": {
        "tags": ["Bulk operations"],
        "summary": "Threat-intel feed bulk ingest",
        "description": (
            "Bulk-insert TI indicators. Distinct from `POST /api/3/insert/indicators`: the feed-ingest "
            "path bypasses on-create playbook triggers (intentional for high-volume feeds)."
        ),
        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object"}}}}},
        "responses": {"200": _resp("Ingest result.")},
    },
}

PATHS["/api/insert-feeds/{recordType}"] = {
    "parameters": [{"name": "recordType", "in": "path", "required": True, "schema": {"type": "string"}}],
    "post": {
        "tags": ["Bulk operations"],
        "summary": "Generic feed insert",
        "description": "Generalization of `/api/ingest-feeds/indicators` for any record type. Same trigger-skipping behavior.",
        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object"}}}}},
        "responses": {"200": _resp("Ingest result.")},
    },
}


# --- Query API -------------------------------------------------------------

PATHS["/api/query/{collection}"] = {
    "parameters": [{"name": "collection", "in": "path", "required": True, "schema": {"type": "string"}}],
    "post": {
        "tags": ["Query"],
        "summary": "Ad-hoc query (full grammar)",
        "description": (
            "Full filter / aggregation grammar over a single collection. "
            "Grammar: 13 leaf operators, AND/OR nesting, sort, aggregates "
            "(`count`, `groupby`, `sum`, `avg`, `min`, `max`, ...).\n\n"
            "Pagination is via query string (`?$limit=&$page=`) - body fields named `page`/`pageSize`/`limit` "
            "are silently ignored. Always set a stable `sort` so successive pages don't reshuffle."
        ),
        "parameters": [
            {"name": "$limit", "in": "query", "schema": {"type": "integer", "default": 30, "maximum": 5000}},
            {"name": "$page", "in": "query", "schema": {"type": "integer", "default": 1}},
            {"name": "$search", "in": "query", "description": "Combines with body filters as AND.", "schema": {"type": "string"}},
        ],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/QueryBody"},
            "examples": {
                "basic": {
                    "summary": "Basic AND filter",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "severity.itemValue", "operator": "in", "value": ["High", "Critical"]},
                            {"field": "status.itemValue", "operator": "neq", "value": "Closed"},
                        ],
                        "sort": [{"field": "createDate", "direction": "desc"}],
                    },
                },
                "nested-or": {
                    "summary": "Nested AND/OR with date window",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "createDate", "operator": "gte", "value": 1736380800, "type": "datetime"},
                            {"field": "createDate", "operator": "lte", "value": 1738972800, "type": "datetime"},
                            {
                                "logic": "OR",
                                "filters": [
                                    {"field": "severity.itemValue", "operator": "eq", "value": "Critical"},
                                    {"field": "tags.itemValue", "operator": "in", "value": ["high-fidelity", "exec-impersonation"]},
                                ],
                            },
                        ],
                        "sort": [{"field": "modifyDate", "direction": "desc"}],
                    },
                },
                "aggregate-groupby": {
                    "summary": "Aggregation: count by severity",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "createDate", "operator": "gte", "value": 1735689600, "type": "datetime"},
                        ],
                        "aggregates": [
                            {"operator": "groupby", "field": "severity.itemValue", "alias": "severity"},
                            {"operator": "count", "field": "*", "alias": "n"},
                        ],
                        "sort": [{"field": "n", "direction": "desc"}],
                    },
                },
                "projection": {
                    "summary": "Field projection (hydrate only what you need)",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "status.itemValue", "operator": "eq", "value": "Open"},
                        ],
                        "aggregates": [
                            {"operator": "fields", "field": "uuid", "alias": "uuid"},
                            {"operator": "fields", "field": "name", "alias": "name"},
                            {"operator": "fields", "field": "severity.itemValue", "alias": "severity"},
                            {"operator": "fields", "field": "createDate", "alias": "createDate"},
                        ],
                    },
                },
                "json-contains": {
                    "summary": "JSON containment + existence on a JSON column",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "rawData", "operator": "contains", "value": {"sourceProduct": "FortiGate"}},
                            {"field": "rawData.indicators", "operator": "exists", "value": True},
                        ],
                    },
                },
                "selectFields": {
                    "summary": "Allowlist response fields with __selectFields",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "status.itemValue", "operator": "eq", "value": "Open"},
                        ],
                        "__selectFields": ["id", "uuid", "name", "severity", "status", "createDate"],
                        "sort": [{"field": "createDate", "direction": "desc"}],
                    },
                },
                "ignoreFields": {
                    "summary": "Denylist response fields with __ignoreFields (export-friendly)",
                    "value": {
                        "logic": "AND",
                        "filters": [
                            {"field": "createDate", "operator": "gte", "value": 1735689600, "type": "datetime"},
                        ],
                        "__ignoreFields": ["createDate", "createUser", "modifyDate", "modifyUser", "@settings"],
                    },
                },
            },
        }}},
        "responses": {"200": _resp("Hydra collection of matching records.", ref="HydraCollection")},
    },
}

PATHS["/api/query/{collection}/{queryId}"] = {
    "parameters": [
        {"name": "collection", "in": "path", "required": True, "schema": {"type": "string"}},
        {"name": "queryId", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}},
    ],
    "post": {
        "tags": ["Query"],
        "summary": "Execute a persisted query",
        "description": (
            "Runs a saved Query previously created via `POST /api/3/user_queries` "
            "(persistent store; system-owned queries live under `/api/3/system_queries`). "
            "Body may override pagination / sort."
        ),
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "$limit": {"type": "integer"},
                "$page": {"type": "integer"},
                "$orderby": {"type": "string"},
            }},
            "example": {"$limit": 30, "$page": 1, "$orderby": "-createDate"},
        }}},
        "responses": {"200": _resp("Hydra collection.", ref="HydraCollection")},
    },
}

PATHS["/api/search"] = {
    "post": {
        "tags": ["Query"],
        "summary": "Global Elasticsearch search",
        "description": (
            "Cross-module text search backed by Elasticsearch. **Min 3 chars** enforced. "
            "Team / RBAC scoped automatically. Use this for global-search-bar UX; for "
            "deterministic per-entity filtering prefer `POST /api/query/<collection>`.\n\n"
            "*Heads-up:* Some 7.6.x builds return 500 here with a server-side TypeError. "
            "Verify on your appliance."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["q", "index"], "properties": {
                "q": {"type": "string", "minLength": 3},
                "index": {"type": "array", "items": {"type": "string"}, "minItems": 1, "example": ["alerts", "incidents"]},
                "size": {"type": "integer", "default": 30},
                "offset": {"type": "integer", "default": 0},
                "searchType": {"type": "string", "default": "_default"},
                "modifyDateGte": {"type": "integer"},
                "modifyDateLte": {"type": "integer"},
            }},
            "example": {"q": "fortinet phishing", "index": ["alerts", "incidents"], "size": 30},
        }}},
        "responses": {"200": _resp("Hits payload.")},
    },
}


# --- Audit gateway ---------------------------------------------------------

_audit_body = {
    "type": "object",
    "required": ["startDate", "endDate"],
    "properties": {
        "startDate": {"$ref": "#/components/schemas/EpochMs"},
        "endDate": {"$ref": "#/components/schemas/EpochMs"},
        "page": {"type": "integer", "default": 0, "description": "0-indexed."},
        "limit": {"type": "integer", "default": 10, "description": "**Default 10** if you misname this param (server silently uses default)."},
        "operation": {"$ref": "#/components/schemas/AuditOperation"},
        "component": {"type": "string", "enum": ["das", "crudhub", "sealab", "agent", "sdk"]},
        "userId": {"type": "string", "description": "Login id (not display name). `user` field is silently ignored."},
        "entityType": {"type": "string", "example": "alerts"},
        "search": {"type": "string", "description": "Free-text - unreliable; returns 0 hits in many cases."},
    },
}

PATHS["/api/gateway/audit/activities"] = {
    "post": {
        "tags": ["Audit"],
        "summary": "Query audit log slice",
        "description": (
            "Returns a slice of audit records for `[startDate, endDate]`. "
            "**Slice pagination** - response has no `totalElements` / `totalPages` / `last`. "
            "Detect end-of-data via empty `content` or `content.length < limit`. For totals use the sibling `/count` endpoint."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": _audit_body,
            "example": {"startDate": 1761696000000, "endDate": 1764288000000, "page": 0, "limit": 100, "operation": "Login Success"},
        }}},
        "responses": {"200": _resp("Slice of records.", example={"content": [{"id": 1, "transactionDate": 1764288000000, "operation": "Login Success", "component": "das", "userId": "csadmin"}]})},
    },
    "delete": {
        "tags": ["Audit"],
        "summary": "Wholesale purge (research)",
        "description": "Mass-delete by body filter. Behavior unverified in this curated pass; treat as risky. See TODOS.",
        "responses": {"200": _resp("Purge result.")},
    },
}

PATHS["/api/gateway/audit/activities/count"] = {
    "post": {
        "tags": ["Audit"],
        "summary": "Total record count for window",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": _audit_body,
            "example": {"startDate": 1735689600000, "endDate": 1764288000000},
        }}},
        "responses": {"200": _resp("Count.", example={"total": 5918})},
    },
}

PATHS["/api/gateway/audit/activities/{auditId}"] = {
    "parameters": [{"name": "auditId", "in": "path", "required": True, "schema": {"type": "integer"}}],
    "get": {
        "tags": ["Audit"],
        "summary": "Single audit record by id",
        "responses": {"200": _resp("Record.", ref="RecordLog")},
    },
}

PATHS["/api/gateway/audit/operations"] = {
    "get": {
        "tags": ["Audit"],
        "summary": "Valid operation values (picklist)",
        "responses": {"200": _resp("Plain JSON array of strings.",
                                   example=["Create", "Update", "Delete", "Login Success", "Login Failed"])},
    },
}

PATHS["/api/gateway/audit/activities/ttl"] = {
    "delete": {"tags": ["Audit"], "summary": "Disable TTL (stop auto-purge of audit logs)",
               "description": "Documented Fortinet recipe to **stop automatic purging of audit logs**. `DELETE` with `Authorization: Bearer <token>` returns 200.",
               "responses": {"200": _resp("Disabled.")}},
}


# --- Workflows / triggers --------------------------------------------------

# Filters and pagination params are shared across recent (`/workflows/`),
# log_list (`/workflows/log_list/`), and historical (`/historical-workflows/`)
# views, so define them once and reuse.
_WF_LIST_PARAMS = [
    {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
    {"name": "limit", "in": "query", "schema": {"type": "integer"},
     "description": "Maximum number of results to return per page."},
    {"name": "offset", "in": "query", "schema": {"type": "integer"},
     "description": "Index from which to start returning results."},
    {"name": "ordering", "in": "query", "schema": {"type": "string"},
     "description": "Sort field; prefix `-` for descending. Common: `-modified`, `-created`."},
    {"name": "page", "in": "query", "schema": {"type": "integer"}},
    {"name": "status", "in": "query", "schema": {"type": "string",
        "enum": ["incipient", "active", "pending", "running", "failed",
                 "finished", "awaiting", "skipped", "terminated", "paused"]},
     "description": "Filter by run state."},
    {"name": "task_id", "in": "query", "schema": {"type": "string"},
     "description": "Match the `task_id` returned by a trigger POST. Pair with `parent_wf__isnull=True` to skip sub-playbook children."},
    {"name": "template_iri", "in": "query", "schema": {"type": "string"},
     "description": "Filter by playbook IRI (e.g. `/api/3/workflows/<uuid>`). Returns history for that specific playbook."},
    {"name": "records", "in": "query", "schema": {"type": "string"},
     "description": "Filter by record IRI (e.g. `/api/3/alerts/<uuid>`). Returns runs that executed against that record."},
    {"name": "created_after", "in": "query", "schema": {"type": "string", "format": "date"},
     "description": "Inclusive lower bound on `created` (ISO date, e.g. `2024-11-08`). Pair with `created_before` for a window."},
    {"name": "created_before", "in": "query", "schema": {"type": "string", "format": "date"},
     "description": "Inclusive upper bound on `created` (ISO date)."},
    {"name": "parent_wf__isnull", "in": "query", "schema": {"type": "boolean"},
     "description": "`True` filters out sub-playbook children (only parent runs returned). On `/historical-workflows/` the equivalent flag is `parent__isnull`."},
    {"name": "tags_include", "in": "query", "schema": {"type": "string"},
     "description": "Comma-separated tag allowlist - only runs carrying any of these tags are returned."},
    {"name": "tags_exclude", "in": "query", "schema": {"type": "string"},
     "description": "Comma-separated tag denylist - runs carrying any of these tags are filtered out. Combinable with `tags_include`."},
]


PATHS["/api/wf/api/workflows/"] = {
    "get": {
        "tags": ["Workflows"],
        "summary": "List recent playbook runs",
        "description": (
            "Hydra-paged list of recent playbook execution logs. **Recent** here means runs that have not "
            "yet been moved to historical storage by the Playbook Log Movement task (runs every 15 minutes "
            "for completed playbooks, 60 minutes for failed/terminated; configurable in System Configuration).\n\n"
            "For runs older than that, use `GET /api/wf/api/historical-workflows/`. To combine both stores in "
            "a single query, use `POST /api/wf/api/query/workflow_logs/?logs=all`.\n\n"
            "Common patterns:\n\n"
            "- `task_id=<uuid>` (with `parent_wf__isnull=True`) — look up the run created by a trigger POST, "
            "  skipping sub-playbook children.\n"
            "- `ordering=-modified` + `limit=1` — newest run first.\n"
            "- `template_iri=/api/3/workflows/<uuid>` — runs of a specific playbook.\n"
            "- `records=/api/3/alerts/<uuid>` — runs executed against a specific record.\n"
            "- `status=failed&created_after=2024-11-08&created_before=2024-11-10` — failed runs in a window.\n"
            "- `tags_include=ingestion,critical&tags_exclude=system` — tag allow/deny lists.\n\n"
            "Each `hydra:member` entry has `status` (one of `incipient`, `active`, `pending`, `running`, "
            "`finished`, `failed`, `awaiting`, `skipped`, `terminated`, `paused`) and `@id` — the trailing "
            "segment is the workflow pk used by the per-run detail GET."
        ),
        "parameters": _WF_LIST_PARAMS,
        "responses": {"200": _resp("Hydra collection of recent runs.")},
    },
}

PATHS["/api/wf/api/workflows/{pk}/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Workflow pk (the trailing segment of the `@id` from a list result). Numeric on this build."}],
    "get": {
        "tags": ["Workflows"],
        "summary": "Recent run detail",
        "description": (
            "Full execution record for one recent playbook run. `result` is a dict keyed by step UUID with "
            "each step's output — this is where playbook return values live. Use after polling the list "
            "endpoint by `task_id` and seeing a terminal `status`.\n\n"
            "If the run has been moved to historical storage, this returns 404. Refetch from "
            "`GET /api/wf/api/historical-workflows/{pk}/` in that case."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"200": _resp("Workflow detail with `result`, `name`, `status`, step trace.")},
    },
}

PATHS["/api/wf/api/workflows/log_list/"] = {
    "post": {
        "tags": ["Workflows"],
        "summary": "Status lookup by `task_id`",
        "description": (
            "Returns the status of one or more executing playbooks identified by `task_id`. The `task_id` "
            "is what a trigger POST returns (top-level on `/api/triggers/1/{name}`, sometimes nested under "
            "`data` for legacy triggers).\n\n"
            "Pagination + sort + filter params are passed in the query string; the request body is empty `{}`. "
            "Pair `task_id=<uuid>` with `parent_wf__isnull=True` to skip sub-playbook child runs.\n\n"
            "Example: `POST /api/wf/api/workflows/log_list/?format=json&limit=10&offset=0&ordering=-modified"
            "&page=1&task_id=c762219d-947a-483e-8818-e2795dbc1b7b&parent_wf__isnull=True`"
        ),
        "parameters": _WF_LIST_PARAMS,
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object"}, "example": {},
        }}},
        "responses": {"200": _resp("Hydra collection of matching runs.")},
    },
}

PATHS["/api/wf/api/historical-workflows/"] = {
    "get": {
        "tags": ["Workflows"],
        "summary": "List historical playbook runs",
        "description": (
            "Hydra-paged list of playbook runs that have been moved to historical storage (added in 7.6.1). "
            "Same filter grammar as `/api/wf/api/workflows/` with one nit: the parent-only filter is named "
            "`parent__isnull` here (vs `parent_wf__isnull` on the recent endpoint).\n\n"
            "Use `GET /api/wf/api/workflows/count?logs=all` for a combined count across recent + historical."
        ),
        "parameters": _WF_LIST_PARAMS + [
            {"name": "parent__isnull", "in": "query", "schema": {"type": "boolean"},
             "description": "Historical-only equivalent of `parent_wf__isnull` — `True` filters out sub-playbook children."},
        ],
        "responses": {"200": _resp("Hydra collection of historical runs.")},
    },
}

PATHS["/api/wf/api/historical-workflows/{pk}/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Historical workflow pk (trailing segment of `@id`)."}],
    "get": {
        "tags": ["Workflows"],
        "summary": "Historical run detail",
        "description": (
            "Detail view for one historical playbook run. Shape mirrors `/api/wf/api/workflows/{pk}/` — "
            "`result` per-step output, `template_iri` to the source playbook, `created`/`modified` timestamps, "
            "`env` snapshot."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"200": _resp("Historical run detail.")},
    },
}

PATHS["/api/wf/api/query/workflow_logs/"] = {
    "post": {
        "tags": ["Workflows"],
        "summary": "Query playbook logs (recent + historical)",
        "description": (
            "POST-body query against the playbook log store. `?logs=all` (default) combines recent and "
            "historical; `?logs=recent` or `?logs=historical` restrict to one source.\n\n"
            "If the request body is `{\"query\": {}}` (or any non-empty body), filtering uses the body's "
            "grammar (`logic`, `filters`, `sort`, `aggregates`) — same shape as `POST /api/query/{collection}`. "
            "Otherwise URL query params drive the result set.\n\n"
            "Supported leaf operators for `filters`: `eq`, `neq`, `contains`, `ncontains`, `gte`, `lte`. "
            "Filterable fields include `status`, `user`, `tags`, `modified`, `name`. `aggregates` supports "
            "`groupBy` and `count` over `status`, `user`, `name`, `id`. Logic groups (`AND` / `OR`) nest."
        ),
        "parameters": [
            {"name": "logs", "in": "query",
             "schema": {"type": "string", "enum": ["all", "recent", "historical"], "default": "all"},
             "description": "Source of the playbook logs to search."},
        ],
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "logic": {"type": "string", "enum": ["AND", "OR"]},
                "limit": {"type": "integer"},
                "sort": {"type": "array", "items": {"type": "object", "properties": {
                    "field": {"type": "string"},
                    "direction": {"type": "string", "enum": ["asc", "desc"]},
                }}},
                "filters": {"type": "array", "items": {"type": "object"}},
                "aggregates": {"type": "array", "items": {"type": "object"}},
            }},
            "examples": {
                "flat": {
                    "summary": "Flat AND with sort",
                    "value": {
                        "logic": "AND",
                        "limit": 30,
                        "sort": [{"field": "modified", "direction": "desc"}],
                        "filters": [
                            {"field": "status", "operator": "eq", "value": "finished"},
                        ],
                    },
                },
                "nested": {
                    "summary": "Nested OR groups",
                    "value": {
                        "logic": "OR",
                        "limit": 30,
                        "filters": [
                            {"logic": "OR", "filters": [
                                {"field": "tags", "operator": "contains", "value": "test"},
                                {"field": "tags", "operator": "contains", "value": "testing"},
                            ]},
                            {"logic": "AND", "filters": [
                                {"field": "status", "operator": "eq", "value": "finished"},
                                {"field": "status", "operator": "eq", "value": "failed"},
                            ]},
                        ],
                    },
                },
                "aggregate": {
                    "summary": "Count grouped by status",
                    "value": {
                        "logic": "AND",
                        "filters": [],
                        "aggregates": [
                            {"operator": "groupBy", "field": "status"},
                            {"operator": "count", "field": "id"},
                        ],
                    },
                },
            },
        }}},
        "responses": {"200": _resp("Hydra collection of matching log rows.")},
    },
}

PATHS["/api/wf/api/workflows/count/"] = {
    "get": {"tags": ["Workflows"], "summary": "Workflow count",
            "description": (
                "Total run count. `?logs=all` (default) combines recent + historical; pass `logs=recent` or "
                "`logs=historical` to restrict.\n\n"
                "**Trailing slash matters.** `/api/wf/api/workflows/count` (no slash) hits an HMAC-gated handler "
                "that returns `403 \"Could not validate HMAC fingerprint\"` under Bearer or API-KEY; the "
                "slashed form `/api/wf/api/workflows/count/` returns the count under either auth."
            ),
            "parameters": [
                {"name": "logs", "in": "query",
                 "schema": {"type": "string", "enum": ["all", "recent", "historical"], "default": "all"},
                 "description": "Source of the count."},
                {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
            ],
            "responses": {"200": _resp("Count.", example={"count": 1667})}},
}

_WF_ACTION_BODIES = {
    "start": ({"type": "object"}, {}),
    "resume": ({"type": "object"}, {}),
    "retry": ({"type": "object"}, {}),
    "approval": (
        {"type": "object", "properties": {
            "decision": {"type": "string", "enum": ["approved", "rejected"]},
            "comment": {"type": "string"},
        }},
        {"decision": "approved", "comment": "looks good"},
    ),
}
for action, desc in [
    ("start", "Manually queue a workflow."),
    ("resume", "Resume a paused workflow (status=`paused`; for `awaiting`, use the manual-input PUT)."),
    ("retry", "Retry a failed workflow from the failed step."),
    ("approval", "Approval-step shortcut. Body shape unverified; expected `{decision, comment}`."),
]:
    _schema, _example = _WF_ACTION_BODIES[action]
    PATHS[f"/api/wf/api/workflows/{{pk}}/{action}/"] = {
        "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"}}],
        "post": {"tags": ["Workflows"], "summary": f"Workflow {action}", "description": desc,
                 "requestBody": {"required": False, "content": {"application/json": {
                     "schema": _schema, "example": _example,
                 }}},
                 "responses": {"200": _resp("Action result.")}},
    }

PATHS["/api/wf/api/jinja-editor/"] = {
    "post": {
        "tags": ["Workflows"],
        "summary": "Render a Jinja template",
        "description": "Live Jinja evaluation. Supports ~144 filters (Jinja2 + Ansible + FortiSOAR-specific). YAQL also available via `| yaql(...)` in 7.2.0+.",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "properties": {"template": {"type": "string"}, "values": {"type": "object"}}, "required": ["template"]},
            "example": {"template": "{{ alert.name | upper }}", "values": {"alert": {"name": "phish-001"}}},
        }}},
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"200": _resp("Rendered output.")},
    },
}

PATHS["/api/wf/api/manual-wf-input/list_wfinput/"] = {
    "post": {"tags": ["Workflows"], "summary": "List pending manual inputs",
             "description": "GET on this path returns 405 - must be POST.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {},
             }}},
             "responses": {"200": _resp("Collection of pending inputs.")}},
}

PATHS["/api/triggers/1/{name}"] = {
    "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "User-defined endpoint name from a Custom API Endpoint trigger."}],
    "post": {
        "tags": ["Triggers"],
        "summary": "Custom playbook trigger",
        "description": (
            "Fires a playbook by its trigger's arbitrary endpoint name. May allow Basic auth or no-auth depending on trigger config (intentional, for external webhooks).\n\n"
            "Response always carries a `task_id` (sometimes top-level, sometimes nested under `data`). Track the run via `GET /api/wf/api/workflows/?task_id=<task_id>&parent_wf__isnull=True` and fetch full results from `GET /api/wf/api/workflows/{pk}/`. See [Triggering a playbook with an API key and tracking the task](#description/triggering-a-playbook-with-an-api-key-and-tracking-the-task)."
        ),
        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {"200": _resp("Trigger accepted.", example={"task_id": "9c0e8a3a-1b2d-4f56-9a8b-1234567890ab"})},
    },
}

PATHS["/api/triggers/1/deferred/{name}"] = {
    "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}],
    "post": {"tags": ["Triggers"], "summary": "Custom trigger (deferred / async)",
             "description": "Same shape as `POST /api/triggers/1/{name}` but always returns 202 and runs the playbook on a worker.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {},
             }}},
             "responses": {"202": _resp("Accepted.")}},
}

PATHS["/api/triggers/1/notrigger/{workflowId}"] = {
    "parameters": [{"name": "workflowId", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "post": {"tags": ["Triggers"], "summary": "Run workflow by id without firing trigger conditions",
             "description": "Direct execution by workflow UUID, bypassing trigger filters. Use for debugging / forced replay.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object", "description": "Arbitrary input payload exposed to the workflow."},
                 "example": {},
             }}},
             "responses": {"200": _resp("Run result.")}},
}


# --- Integration / connectors ---------------------------------------------
# Paths are ordered to match the connector lifecycle flow described in the
# Connectors tag: install -> list -> configure -> execute -> healthcheck ->
# delete config -> uninstall. The Redoc UI renders ops in dict-insertion
# order within a tag, so reordering here reorders the rendered docs.

# Step 1: install from .tgz (multipart upload).
PATHS["/api/3/solutionpacks/install"] = {
    "post": {
        "tags": ["Connectors"],
        "summary": "Install a connector from a .tgz bundle",
        "description": (
            "Multipart upload of a connector `.tgz`. The `$type=connector` query parameter is required; "
            "`$replace=true` re-installs over an existing version. The response carries the full connector "
            "record including the integer `id` you'll need for subsequent steps."
        ),
        "parameters": [
            {"name": "$type", "in": "query", "required": True, "schema": {"type": "string", "enum": ["connector"]}},
            {"name": "$replace", "in": "query", "schema": {"type": "boolean"},
             "description": "Replace an existing install of the same name+version."},
        ],
        "requestBody": {"required": True, "content": {"multipart/form-data": {
            "schema": {"type": "object", "required": ["file"], "properties": {
                "file": {"type": "string", "format": "binary",
                         "description": "The connector `.tgz` archive."},
            }},
        }}},
        "responses": {"200": _resp("Installed connector record (with integer `id`).")},
    },
}

# Step 2: list installed connectors (also: source-of-truth for the integer id).
# Pagination uses Django REST style params (`page_size`, `page`), **not** the
# Hydra `limit`/`offset` you see under `/api/3/`. Reused by the configuration
# list below.
_INTEGRATION_LIST_PARAMS = [
    {"name": "page_size", "in": "query", "schema": {"type": "integer"},
     "description": "Records per page. Default 30."},
    {"name": "page", "in": "query", "schema": {"type": "integer"},
     "description": "1-based page number."},
    {"name": "name", "in": "query", "schema": {"type": "string"},
     "description": "Filter by exact connector name (e.g. `hello-world`)."},
    {"name": "active", "in": "query", "schema": {"type": "boolean"},
     "description": "Filter to active/inactive records."},
]

PATHS["/api/integration/connectors/"] = {
    "get": {"tags": ["Connectors"], "summary": "List installed connectors",
            "description": "Response envelope is a custom shape (`status`, `totalItems`, `data[]`), **not** a Hydra collection. Each `data[]` entry carries an integer `id`, `name`, `version`, `status` (e.g. `Completed`).",
            "parameters": _INTEGRATION_LIST_PARAMS,
            "responses": {"200": _resp("Collection envelope.")}},
}

# Step 3: list / create configurations.
PATHS["/api/integration/configuration/"] = {
    "get": {"tags": ["Connectors"], "summary": "List connector configurations",
            "description": "Returns the same envelope shape as `/api/integration/connectors/` (`data[]`, not Hydra). Each entry has `id` (int), `config_id` (uuid), `connector` (int connector id), `agent` (self-agent hash when remote), `config` (field map).",
            "parameters": _INTEGRATION_LIST_PARAMS,
            "responses": {"200": _resp("Collection envelope.")}},
    "post": {"tags": ["Connectors"], "summary": "Create connector configuration",
             "description": (
                 "Required body fields: `name`, `connector` (integer connector id — not the name), `config` "
                 "(map of the connector's configuration field values). `default`, `status`, and `teams` "
                 "are optional.\n\n"
                 "**`agent` is optional.** Set it only when delegating execution to a **remote agent**; "
                 "omit it (or leave unset) to run on the appliance's self-agent, which is the default."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "required": ["name", "connector", "config"], "properties": {
                     "name": {"type": "string"},
                     "connector": {"type": "integer"},
                     "config": {"type": "object"},
                     "agent": {"type": "string",
                               "description": "Remote agent identifier. Omit for self-agent execution."},
                     "default": {"type": "boolean"},
                     "status": {"type": "integer"},
                     "teams": {"type": "array", "items": {"type": "string"}},
                 }},
             }}},
             "responses": {"201": _resp("Created.")}},
}

# Step 4: execute a connector action.
PATHS["/api/integration/execute/"] = {
    "post": {
        "tags": ["Connectors"],
        "summary": "Execute a connector action",
        "description": "Runs a connector operation. Body shape varies per operation - it is the action's input payload as defined by the connector's `info.json`.",
        "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}, "description": "Connector name."}],
        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {"200": _resp("Action result.")},
    },
}

# Step 5a: healthcheck — GET form using an existing config (cheap).
PATHS["/api/integration/connectors/healthcheck/{name}/{version}/"] = {
    "parameters": [
        {"name": "name", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector name (e.g. `hello-world`)."},
        {"name": "version", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector version (e.g. `1.0.4`)."},
    ],
    "get": {"tags": ["Connectors"], "summary": "Health-check a connector via existing config",
            "description": "Lighter-weight check than the POST form: takes the configuration uuid as a query parameter rather than re-sending the full config body.",
            "parameters": [
                {"name": "config", "in": "query", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                 "description": "Configuration uuid (`config_id`)."},
            ],
            "responses": {"200": _resp("Health status with `status: Available` on success.")}},
}

# Step 5b: healthcheck — POST form when re-sending a full config inline.
PATHS["/api/integration/connectors/healthcheck/"] = {
    "post": {"tags": ["Connectors"], "summary": "Health-check a connector configuration (inline body)",
             "description": (
                 "Body must carry a full connector configuration object (connector name/version + config "
                 "fields). An empty or wrong-shape body returns 404 with a generic message rather than 400. "
                 "For the cheaper GET form (uses an already-created config), see "
                 "`/api/integration/connectors/healthcheck/{name}/{version}/`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
             "responses": {"200": _resp("Health status.")}},
}

# Step 6a: delete the configuration.
PATHS["/api/integration/configuration/{config_id}/"] = {
    "parameters": [{"name": "config_id", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "Configuration uuid (the `config_id` field, not the integer `id`)."}],
    "delete": {"tags": ["Connectors"], "summary": "Delete a connector configuration",
               "description": (
                   "**Two non-obvious requirements:** the path param must be the uuid (`config_id`), not "
                   "the integer DB id (which returns 500), and the **trailing slash is mandatory** — "
                   "without it the request is routed to an HMAC-gated handler that returns the misleading "
                   "`403 Could not validate HMAC fingerprint`."
               ),
               "responses": {"204": {"description": "Deleted."}}},
}

# Step 6b: uninstall the connector.
PATHS["/api/integration/connectors/{id}/"] = {
    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    "description": "Integer connector id (`data[].id` from `/api/integration/connectors/`)."}],
    "delete": {"tags": ["Connectors"], "summary": "Uninstall a connector",
               "description": "Trailing slash is required. Returns 204 on success.",
               "responses": {"204": {"description": "Uninstalled."}}},
}


# --- Modules / metadata ----------------------------------------------------

PATHS["/api/3/model_metadatas"] = {
    "get": {"tags": ["Metadata"], "summary": "List module / model definitions",
            "description": "Drift-resistant alternative to a static schema snapshot.",
            "responses": {"200": _resp("Collection of ModelMetadata.")}},
}

PATHS["/api/3/picklists/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist value",
            "description": (
                "Resolves one picklist *value* record by uuid - the leaf entries that record fields point at "
                "(`severity`, `status`, etc.). The owning picklist taxonomy is `GET /api/3/picklist_names/{uuid}`."
            ),
            "responses": {"200": _resp("Picklist record.")}},
}

PATHS["/api/3/picklist_names/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist taxonomy",
            "description": (
                "Resolves one picklist *taxonomy* record by uuid - the named list (e.g. `AlertSeverity`) "
                "whose members are exposed via `GET /api/3/picklists/{uuid}`."
            ),
            "responses": {"200": _resp("Picklist name record.")}},
}

PATHS["/api/3/contexts/{shortName}"] = {
    "parameters": [{"name": "shortName", "in": "path", "required": True, "schema": {"type": "string"}}],
    "get": {"tags": ["Metadata"], "summary": "Hydra @context for a model",
            "description": "Authoritative property list for one entity. Returns `application/ld+json`.",
            "responses": {"200": _resp("JSON-LD context.")}},
}

PATHS["/api/3/docs.jsonld"] = {
    "get": {
        "tags": ["Metadata"],
        "summary": "Hydra ApiDocumentation (full surface)",
        "description": (
            "Walks `hydra:supportedClass` for every entity (114 classes on 7.6.5). "
            "Per-entity properties + supported operations. Less ergonomic than OpenAPI but "
            "exhaustive - use as the source of truth when expanding this curated spec.\n\n"
            "Note: `/api/3/docs.json` returns 'Format \"json\" is not supported' on this build; only `.jsonld` works."
        ),
        "responses": {"200": _resp("ApiDocumentation (JSON-LD).")},
    },
}


# --- Files / attachments --------------------------------------------------

PATHS["/api/3/files"] = {
    "post": {
        "tags": ["Files"],
        "summary": "Upload a file / attachment",
        "description": "Multipart upload. Used by every connector that captures evidence and as the first step of import-job ingestion.",
        "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
            "type": "object",
            "properties": {"file": {"type": "string", "format": "binary"}},
            "required": ["file"],
        }}}},
        "responses": {"201": _resp("File record (carries `@id` for use as IRI ref).")},
    },
}


# --- API keys / RBAC -------------------------------------------------------

# Roles and teams keep the generic list/create shape; API keys gets a richer
# dedicated section below.
for path, tag, summary in [
    ("/api/3/roles", "Access management", "Roles"),
    ("/api/3/teams", "Access management", "Teams"),
]:
    PATHS[path] = {
        "get": {"tags": [tag], "summary": f"List {summary.lower()}", "parameters": COMMON_QPARAMS,
                "description": (
                    f"Hydra-paged listing of all {summary.lower()} in the tenant. Same `$`-param grammar "
                    f"as any other record collection."
                ),
                "responses": {"200": _resp("Collection.", ref="HydraCollection")}},
        "post": {"tags": [tag], "summary": f"Create {summary.lower()[:-1]}",
                 "description": (
                     f"Creates a new {summary.lower()[:-1]}. Body shape follows the generic record contract "
                     f"(`name` plus module-specific fields); see `GET /api/3/contexts/{summary[:-1]}` for the "
                     f"full property list."
                 ),
                 "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
                 "responses": {"201": _resp("Created.")}},
    }

# API-key lifecycle is a multi-step workflow split across `/api/auth/users`
# (the user record carrying the key) and `/api/3/api_keys` (the named scope
# binding the user to roles + teams).
#
# Create flow:
#   1. POST /api/auth/users  with type=9 (API-key user) -> returns uuid + key.
#   2. POST /api/3/api_keys  with userId=<that uuid> + roles + teams -> binds scope.
# Lifecycle ops (revoke / activate / deactivate / regenerate / reset_validity)
# are all PUT /api/auth/users with an `operation` discriminator.

PATHS["/api/3/api_keys"] = {
    "get": {
        "tags": ["Access management"],
        "summary": "List API-key scopes",
        "description": "Returns one object per scope binding (`name`, `uuid`, `userId`, roles, teams). Use `userId` values as input to `POST /api/auth/query/users` to fetch the actual keys.",
        "parameters": COMMON_QPARAMS,
        "responses": {"200": _resp("Hydra collection of scopes.", ref="HydraCollection")},
    },
    "post": {
        "tags": ["Access management"],
        "summary": "Bind an API-key user to roles and teams (step 2 of create)",
        "description": "Run **after** `POST /api/auth/users` returns the API-key user's `uuid`. Pass that `uuid` here as `userId`.",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["name", "userId"], "properties": {
                "name": {"type": "string"},
                "roles": {"type": "array", "items": {"type": "string"}, "description": "Role IRIs (`/api/3/roles/<uuid>`)."},
                "teams": {"type": "array", "items": {"type": "string"}, "description": "Team IRIs (`/api/3/teams/<uuid>`)."},
                "userId": {"type": "string", "description": "User uuid returned by `POST /api/auth/users`."},
            }},
            "example": {
                "name": "api_key_for_automation",
                "roles": ["/api/3/roles/<roleId1>", "/api/3/roles/<roleId2>"],
                "teams": ["/api/3/teams/<teamId1>"],
                "userId": "<userId>",
            },
        }}},
        "responses": {"201": _resp("Scope created.")},
    },
}

PATHS["/api/3/api_keys/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "Scope uuid (from `GET /api/3/api_keys`)."}],
    "get": {
        "tags": ["Access management"],
        "summary": "Get scope of a specific API key",
        "description": (
            "Returns the scope binding (`name`, `uuid`, `userId`, roles, teams) for one API key. "
            "`userId` is the linked API-key user uuid - use it with `/api/auth/users` to manage key material."
        ),
        "responses": {"200": _resp("Scope record (`name`, `uuid`, `userId`, roles, teams).")},
    },
    "put": {
        "tags": ["Access management"],
        "summary": "Update scope (name / roles / teams)",
        "description": "**Replaces** the listed fields — values not in the payload that were previously set are overwritten with the new payload's values, so resend the full roles/teams lists you want to keep.",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "name": {"type": "string"},
                "roles": {"type": "array", "items": {"type": "string"}},
                "teams": {"type": "array", "items": {"type": "string"}},
                "userId": {"type": "string"},
            }},
            "example": {
                "name": "api_key_for_automation",
                "roles": ["/api/3/roles/<roleId1>", "/api/3/roles/<roleId2>"],
                "teams": ["/api/3/teams/<teamId1>"],
                "userId": "<userId>",
            },
        }}},
        "responses": {"200": _resp("Updated scope.")},
    },
}

PATHS["/api/auth/users"] = {
    "get": {
        "tags": ["Access management"],
        "summary": "Get a specific API-key user (optionally with the unmasked key)",
        "description": "Lookup by the API-key user's uuid (the `userId` from `GET /api/3/api_keys`). Default response masks the key; pass `show_api_key=true` to retrieve the plaintext — only works when the key was created with `retrievable_mode` enabled.",
        "parameters": [
            {"name": "uuid", "in": "query", "required": True, "schema": {"type": "string"},
             "description": "API-key user uuid."},
            {"name": "show_api_key", "in": "query", "schema": {"type": "boolean"},
             "description": "Return the unmasked key (subject to `retrievable_mode`)."},
        ],
        "responses": {"200": _resp("API-key user record.")},
    },
    "post": {
        "tags": ["Access management"],
        "summary": "Create an API-key user (step 1 of create)",
        "description": (
            "Creates the underlying user record that carries the key material. The returned `uuid` "
            "feeds `POST /api/3/api_keys` to attach roles and teams. `type=9` is the API-key user "
            "discriminator; `status=1` means active.\n\n"
            "**All three body fields are integers and required.** The published FortiSOAR API guide "
            "shows `type` and `status` as quoted strings (`\"9\"`, `\"1\"`); on tested builds, that shape "
            "is rejected with a generic 400. Use integer literals."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["type", "status", "api_key_validity"], "properties": {
                "type": {"type": "integer", "enum": [9], "description": "`9` = API-key user."},
                "status": {"type": "integer", "enum": [1], "description": "`1` = active."},
                "api_key_validity": {"type": "integer", "minimum": 1, "maximum": 365,
                                     "description": "Validity in days; must be in 1..365."},
            }},
            "example": {"type": 9, "status": 1, "api_key_validity": 1},
        }}},
        "responses": {"201": _resp("User created.", example={
            "uuid": "<user_id_for_api_key>",
            "api_key": {"key": "<api_key_value>", "retrievable": False},
        })},
    },
    "put": {
        "tags": ["Access management"],
        "summary": "API-key lifecycle: revoke / activate / deactivate / regenerate / reset validity",
        "description": (
            "Single endpoint for all five lifecycle ops, discriminated by the `operation` field. "
            "`uuid` here is the API-key user uuid (the `userId` returned by `GET /api/3/api_keys`).\n\n"
            "- `REVOKE` — permanent deactivation.\n"
            "- `ACTIVATE` / `DEACTIVATE` — toggle status.\n"
            "- `REGENERATE` — issue a fresh key; requires `api_key_validity`.\n"
            "- `RESET_VALIDITY` — extend/shorten validity; requires `api_key_validity`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["uuid", "key_type", "operation"], "properties": {
                "uuid": {"type": "string"},
                "key_type": {"type": "string", "enum": ["API_KEY"]},
                "operation": {"type": "string", "enum": ["REVOKE", "ACTIVATE", "DEACTIVATE", "REGENERATE", "RESET_VALIDITY"]},
                "api_key_validity": {"type": "integer", "description": "Required for `REGENERATE` and `RESET_VALIDITY`."},
            }},
            "example": {"uuid": "<uuid>", "key_type": "API_KEY", "operation": "REVOKE"},
        }}},
        "responses": {"200": _resp("Operation applied.")},
    },
}

PATHS["/api/auth/query/users"] = {
    "post": {
        "tags": ["Access management"],
        "summary": "Bulk fetch API-key users by id",
        "description": "Pass a list of API-key user uuids (the `userId` values from `GET /api/3/api_keys`). Keys come back masked by default; `show_api_key=true` returns plaintext for any key whose user was created with `retrievable_mode` enabled.",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["users"], "properties": {
                "users": {"type": "array", "items": {"type": "string"}},
                "show_api_key": {"type": "boolean"},
            }},
            "example": {"users": ["<userId_1>", "<userId_2>"], "show_api_key": True},
        }}},
        "responses": {"200": _resp("Array of API-key user records.")},
    },
}

PATHS["/api/auth/config"] = {
    "get": {
        "tags": ["Access management"],
        "summary": "Read auth config section",
        "description": "Section-scoped config read. Pass `section=API-KEYS` to inspect API-key settings (including `retrievable_mode`).",
        "parameters": [
            {"name": "section", "in": "query", "required": True, "schema": {"type": "string"},
             "description": "Config section, e.g. `API-KEYS`."},
        ],
        "responses": {"200": _resp("Config section payload.")},
    },
    "put": {
        "tags": ["Access management"],
        "summary": "Update an auth config option",
        "description": (
            "Toggle a single option by name/value. The notable API-key option is `retrievable_mode` — when "
            "**enabled at the time a key is created**, that key stays retrievable for its lifetime even if "
            "the global flag is flipped off later. Keys created while it was off can never be retrieved."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["option", "value"], "properties": {
                "option": {"type": "string"},
                "value": {},
            }},
            "example": {"option": "retrievable_mode", "value": True},
        }}},
        "responses": {"200": _resp("Updated.")},
    },
}


# --- Imports / exports ----------------------------------------------------

PATHS["/api/3/import_jobs"] = {
    "post": {
        "tags": ["Import / export"],
        "summary": "Submit an import job (workflow_collections, etc.)",
        "description": (
            "Two-step ingestion: first `POST /api/3/files/` to upload the JSON blob, then create "
            "the import job with `file = /api/3/files/<uuid>` and `type = 'Import Wizard'`.\n\n"
            "**Default `mergeType` is `merge_append`** - existing records (matched by uuid OR "
            "(name, collection)) are silently skipped. For dev-loop overwrite semantics, pass "
            "explicit `options.playbooks.values[].mergeType = 'merge_replace'`.\n\n"
            "*Gotcha:* posting an export-style envelope (`{type, data, ...}`) inline to this "
            "endpoint returns 200 but does nothing - the import-job record has no `data` field, the "
            "denormalizer drops unknown fields, and the worker skips the result. Always go via "
            "the file flow."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["type", "file"], "properties": {
                "type": {"type": "string", "default": "Import Wizard"},
                "file": {"type": "string", "description": "IRI to the uploaded File entity."},
                "options": {"type": "object"},
            }},
            "example": {
                "type": "Import Wizard",
                "file": "/api/3/files/abc123-...",
                "options": {"playbooks": {"include": True, "values": [
                    {"uuid": "<col-uuid>", "name": "<col-name>", "include": True,
                     "mergeType": "merge_replace", "includeSchedules": True},
                ]}},
            },
        }}},
        "responses": {"200": _resp("Import job record.")},
    },
}

PATHS["/api/3/export_jobs"] = {
    "post": {"tags": ["Import / export"], "summary": "Create an export job",
             "description": (
                 "Submits an export job. Body selects which modules and records to include; the resulting "
                 "job record carries a `file` IRI once the worker finishes packaging."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "properties": {
                     "name": {"type": "string"},
                     "type": {"type": "string", "default": "Export Wizard"},
                     "options": {"type": "object"},
                 }, "required": ["name"]},
                 "example": {"name": "weekly-playbooks", "type": "Export Wizard",
                             "options": {"playbooks": {"include": True}}},
             }}},
             "responses": {"200": _resp("Export job record.")}},
}


# --- Misc ------------------------------------------------------------------

PATHS["/api/product/feature-access"] = {
    "get": {"tags": ["System"], "summary": "Feature-flag introspection",
            "description": (
                "License-tier-aware feature-flag map. Each key is a product feature; the boolean indicates "
                "whether the current license unlocks it. Use to gate UI/automation paths without hard-coding "
                "tier checks."
            ),
            "responses": {"200": _resp("Flag map.")}},
}

PATHS["/api/3/cache_util"] = {
    "post": {"tags": ["System"], "summary": "Force cache invalidation",
             "description": (
                 "Flushes internal server-side caches (metadata, picklists, RBAC). Useful after schema or "
                 "role changes when stale lookups would otherwise persist until the next worker restart."
             ),
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {},
             }}},
             "responses": {"200": _resp("OK.")}},
}


# ---------------------------------------------------------------------------
# Spec assembly
# ---------------------------------------------------------------------------

TAG_GROUPS = [
    {"name": "Auth & system", "tags": ["Authentication", "System", "Access management"]},
    {"name": "Records", "tags": ["Records (generic)", "Bulk operations", "Alerts"]},
    {"name": "Query", "tags": ["Query"]},
    {"name": "Audit", "tags": ["Audit"]},
    {"name": "Automation", "tags": ["Workflows", "Triggers", "Connectors"]},
    {"name": "Reference", "tags": ["Metadata", "Files", "Import / export"]},
]

TAG_DESCRIPTIONS = {
    "Authentication": "Token issuance, logout, and current-user / current-actor introspection.",
    "System": "Build version, license info, HA cluster health, feature flags, and cache invalidation. The version + public-license endpoints are unauthenticated; the rest require auth.",
    "Records (generic)": (
        "Every record-bearing entity is exposed at `/api/3/<plural>` with the same Hydra-paged contract. "
        "These two operations document the shared shape; the **Alerts** tag is a worked example."
    ),
    "Alerts": "Concrete CRUD on the `alerts` collection - representative of every record module (`incidents`, `indicators`, `tasks`, `assets`, `people`, ...).",
    "Bulk operations": "High-throughput insert/update/delete/upsert and feed-ingest paths. Note: `/api/ingest-feeds/*` and `/api/insert-feeds/*` skip on-create playbook triggers; `POST /api/3/insert/*` does not.",
    "Query": "Three search surfaces: URL-param (AND only), POST `/api/query/*` body grammar (full AND/OR + aggregates), and global Elasticsearch (`/api/search`). See operation descriptions for when to use which.",
    "Audit": "Audit log query + retention. Slice pagination with no totals - use `/count` separately. Filters are top-level only and accept exactly one value.",
    "Workflows": "Workflow run control, history, and introspection. Lives under `/api/wf/*`.",
    "Triggers": "Fire playbooks - by custom-endpoint name, deferred (async), or by workflow id without firing trigger conditions.",
    "Connectors": (
        "Full connector lifecycle. Per-action request shape comes from each connector's `info.json`.\n\n"
        "**Flow — install → configure → execute → uninstall:**\n\n"
        "1. **Install from `.tgz`** — `POST /api/3/solutionpacks/install?$type=connector&$replace=true` (multipart, field `file` = the binary). Response carries the integer connector `id`.\n"
        "2. **Create a config** — `POST /api/integration/configuration/` with `name`, `connector` (integer id from step 1), and `config` (the connector's field values). Add `agent` only if you want the connector to run on a **remote agent**; omit it to use the appliance's self-agent. Response carries `config_id` (uuid).\n"
        "3. **Execute an action** — `POST /api/integration/execute/` with `connector` name, `version`, `operation`, `config` (the uuid from step 2), and `params`.\n"
        "4. **Health-check** — `GET /api/integration/connectors/healthcheck/{name}/{version}/?config=<uuid>` for the cheap variant (uses an existing config), or the POST form when re-sending a full config inline.\n"
        "5. **Cleanup** — `DELETE /api/integration/configuration/{config_id}/` (uuid + trailing slash), then `DELETE /api/integration/connectors/{id}/` (integer id + trailing slash). The trailing slash is mandatory — without it you'll see `403 Could not validate HMAC fingerprint`."
    ),
    "Metadata": "Module + field schemas, picklist taxonomy, JSON-LD contexts, and the Hydra `ApiDocumentation` (use this to expand the curated surface).",
    "Files": "Attachment upload. Required as the first step of import-job ingestion.",
    "Access management": (
        "API keys, roles, teams.\n\n"
        "**Flow — create → bind → use → lifecycle → revoke:**\n\n"
        "1. **Create the API-key user** — `POST /api/auth/users` with body `{\"type\": 9, \"status\": 1, \"api_key_validity\": <1..365>}`. All three are integers — the published PDF shows quoted strings, which the appliance rejects with 400. Response carries the user `uuid` and the plaintext key.\n"
        "2. **Bind it to roles and teams** — `POST /api/3/api_keys` with `name`, `roles` (IRIs), `teams` (IRIs), and `userId` (the uuid from step 1). Required to make the key actually usable.\n"
        "3. **Read the scope** — `GET /api/3/api_keys/{uuid}` for one binding, or `GET /api/3/api_keys` for the full list.\n"
        "4. **Lifecycle operations** — `PUT /api/auth/users` with `uuid`, `key_type: API_KEY`, and `operation` ∈ `{REVOKE, ACTIVATE, DEACTIVATE, REGENERATE, RESET_VALIDITY}`. `REGENERATE` and `RESET_VALIDITY` also need `api_key_validity`.\n"
        "5. **Bulk fetch with plaintext** — `POST /api/auth/query/users` with `{users: [<uuid>, ...], show_api_key: true}` (only returns plaintext for keys whose user was created with `retrievable_mode` enabled in `/api/auth/config`)."
    ),
    "Import / export": "Configuration import/export. Read the `import_jobs` description carefully - the inline-envelope shape is a silent no-op.",
}


REFERENCE_PROSE = r"""A hand-shaped OpenAPI 3.1 reference for the FortiSOAR REST API.

> **Disclaimer.** This reference is a community effort and is **not exhaustive**. Coverage is the surface I use day-to-day; many operations are still missing. Operations stamped with **Live-verified** at the top of the page were exercised end-to-end against a real FortiSOAR. Anything without that stamp is documented from the API guide and DB introspection only - request/response shapes are best-effort, not guaranteed to be correct. Always validate against your own appliance before relying on it.
>
> **What the Live-verified line tells you.** It looks like: **Live-verified** (`apikey: OK` - `jwt: OK`, YYYY-MM-DD).
>
> - `apikey: OK` / `jwt: OK` - the verifier called the operation with that auth mode and got a 2xx response. Captured (sanitized) responses are folded into the `200` example.
> - `apikey: 401` (or `403`, `404`, ...) - that auth mode returned the listed status code. Some endpoints only accept one auth mode; that's fine, just means the other won't work for you either.
> - Trailing date - when the verifier last hit this op.
> - No Live-verified line at all - never executed by the verifier. Treat as documentation-only.

Schemas (`Alert`, `RecordLog`, ...) are validated against captured responses where present. Run `python src/verify_curated.py` against your FortiSOAR (creds in `.env`) to refresh the verification report.

## Concepts

The entire API is **JSON-LD + Hydra**. Every record carries `@id` (its IRI), `@type` (entity name), and `@context` (model URL). Collections wrap records in a `hydra:Collection` envelope (see [Pagination & response shape](#description/pagination-response-shape)).

- **IRI** (Internationalized Resource Identifier) - relative URL like `/api/3/alerts/<uuid>`. Used as a foreign-key reference everywhere FK references appear in JSON. Server *generates* `@id` on insert; clients should not send it.
- **UUID** - 36-character hex w/ hyphens. Optional on POST: send your own to retain it for cross-system reference, or omit and read it back from the response IRI.
- **CamelCase** - every key is camelCase (`sourceId`, `dueDate`, `hydra:variableRepresentation`). Use the same convention for any custom modules.
- **Picklist values are IRIs from 7.5.0+.** Posting `"severity": "High"` is rejected; you must post `"severity": "/api/3/picklists/<value-uuid>"`. Fetch the value's IRI from `GET /api/3/picklists?listName.name=AlertSeverity&itemValue=High`. Bulk-feed paths are an exception (no validation).
- **Trigger-bypass semantics.** `POST /api/ingest-feeds/*` and `POST /api/insert-feeds/*` skip on-create playbook triggers (intentional, for high-volume feeds). `POST /api/3/insert/*` (with optional `__bulk: true` for batching) does **not** skip triggers.

## Authentication

Three documented methods; only two are recommended.

| Method | Header | When to use |
|---|---|---|
| **API key** (recommended) | `Authorization: API-KEY <key>` (note literal space) | Appliances, scheduled jobs, long-lived integrations. Mint via Settings -> Security Management -> Access Keys. |
| **Bearer JWT** | `Authorization: Bearer <jwt>` | Short-lived / interactive use. Obtain from `POST /auth/authenticate`. Default TTL ~30 min; re-auth on 401. |
| HMAC | (legacy) | Documented in the public PDF for completeness. Out of scope here - most clients should use API key. |

Some endpoints accept only one method. The **`Live-verified`** badge on each op shows per-auth status; `apikey: 403` next to `jwt: 200` means that endpoint is JWT-only on the box we tested. Examples observed: `/api/auth/cluster/health` requires JWT; `/api/auth/license` is JWT-only; most CRUD works with both.

The `/api/version` and `/api/public/license` endpoints are **public** (no auth required).

## Pagination & response shape

Every `GET /api/3/<plural>` returns a Hydra paged collection:

```json
{
  "@context": "/api/3/contexts/Alert",
  "@id": "/api/3/alerts",
  "@type": "hydra:PagedCollection",
  "hydra:totalItems": 1247,
  "hydra:itemsPerPage": 30,
  "hydra:firstPage": "/api/3/alerts",
  "hydra:nextPage":  "/api/3/alerts?$page=2",
  "hydra:lastPage":  "/api/3/alerts?$page=42",
  "hydra:member": [ ... ],
  "hydra:search":  { "@type": "hydra:IriTemplate", "hydra:template": "/api/3/alerts{?}", "hydra:mapping": [] }
}
```

`hydra:member` is the array. The rest is navigation/metadata.

### Reserved query parameters

| Param | Default | Notes |
|---|---|---|
| `$limit` | 30 | Max **5000** (server-enforced cap). |
| `$page` | 1 | 1-indexed. |
| `$orderby` | - | `field` or `-field` for desc. Body `sort[]` is the equivalent on `/api/query`. |
| `$relationships` | `false` | When `true`, FK fields are inlined (e.g. `severity` becomes the picklist record dict instead of an IRI string). |
| `$export` | `false` | Strips identity fields so the result re-imports cleanly. Used by export UI. |
| `$partial` | `false` | When `true`, `hydra:totalItems` is omitted (skips `COUNT(*)`). Useful when paging blindly. |
| `$search` | - | See [Query reference](#description/query-reference) - top-level token, distinct from the per-field `search` operator. |
| `$fields` | - | **Power user** - `?$fields=uuid,name,steps` returns only those columns. Big response-size win on bulk pulls. |

### Power-user URL filtering

These work on every `/api/3/<plural>` endpoint and cover ~90% of what `/api/query/*` does without a body:

- **Nested dot notation** traverses relationships at any depth: `?triggerStep.stepType.name=cybersponse.post_create&triggerStep.arguments.resources$exists=alerts&isActive=true`. Either `.` or `__` works (`steps__stepType__name` ≡ `steps.stepType.name`).
- **Operators** are appended with `$`: `?eventCount$gte=10&eventCount$lt=20`, `?status__itemValue$in=Open|Resolved|InProgress`. Default operator (no `$op` suffix) is `eq`.
- **Existence on collections**: `<rel>.<arrayField>$exists=value` - "find playbooks whose trigger covers this module". Example: `triggerStep.arguments.resources$exists=alerts`.
- **Multiple parts are ANDed.** No way to OR via URL params - repeating a key (`?field=A&field=B`) returns `400 Bad Request`. Use the body endpoint for OR.

## Query reference

Three distinct query surfaces - pick by use case:

| Surface | Endpoint | Filter | Aggregations | Best for |
|---|---|---|---|---|
| URL-param | `GET /api/3/<resource>?...` | AND of leaf ops | none | Single-condition AND; simple lookups |
| Body | `POST /api/query/<resource>` | full AND/OR tree | yes | Anything non-trivial; complex filters; counts |
| Global | `POST /api/search` | keyword `q` | none | Cross-module text search (Elasticsearch) |

### Body grammar for the query endpoint

```jsonc
{
  "logic": "AND" | "OR",
  "filters": [
    { "field": "<path>", "operator": "<op>", "value": <val>, "type": "<type>"? },   // leaf
    { "logic": "AND" | "OR", "filters": [ ... ] }                                    // nested group
  ],
  "sort":       [ { "field": "<path>", "direction": "asc" | "desc" } ],
  "aggregates": [ { "operator": "<op>", "field": "<path>", "alias": "<name>" } ]
}
```

Pagination + `$search` ride on the **query string** (`?$limit=30&$page=2&$search=fortinet`); body fields named `page`/`pageSize`/`limit` are silently ignored.

### Leaf operators

| Operator | Behavior | Notes |
|---|---|---|
| `eq` | exact equality | Default if `operator` omitted. For association IRIs, the UUID is extracted before comparison. |
| `neq` | exact inequality | |
| `lt`, `lte`, `gt`, `gte` | numeric / date comparisons | With `type: "datetime"` + a numeric value, the value is treated as epoch. |
| `in` | match any of N | Accepts `[...]` array or a `\|`-delimited string. **Lowercases** string values. Association IRIs -> UUIDs. |
| `nin` | NOT IN | Generated SQL is `NOT IN (...) OR field IS NULL` - **includes NULL rows by design**. |
| `like` | SQL LIKE | **Lowercases** the value; matches against `LOWER(field)` for non-JSON columns. Wildcards `%` `_`. |
| `notlike` | SQL NOT LIKE | Excluded from `ALL_OPERATORS` whitelist - works in practice but may be UI-hidden / pending deprecation. |
| `contains` | JSON containment | For `jsonb` columns. |
| `exists` | JSON path existence | Undocumented in the public guide; works against JSON-typed columns. |
| `isnull` | `true` -> IS NULL, `false` -> IS NOT NULL | |
| `search` | per-field full-text | **Source-only.** Declared in the parser but every wire form returns 500. Use `$search` instead. |

### Aggregations

| Operator | DQL | Notes |
|---|---|---|
| `fields`, `select` | `SELECT field AS alias` | Selecting raw fields; **does not flip query into aggregate mode**. |
| `count` | `COUNT(field)` | `field: "*"` -> root alias. |
| `countdistinct` | `COUNT(DISTINCT field)` | Omitted from `ALL_OPERATORS` whitelist but works at builder layer. |
| `groupby` | adds `GROUP BY field` | Pair with a metric (`count`/`sum`/...). |
| `distinct` | `DISTINCT field` | |
| `sum`, `max`, `min` | corresponding SQL | |
| `avg`, `median` | corresponding SQL | Constants exist; **omitted from whitelist** (still emit). |

A query is treated as aggregate iff `aggregates[]` contains anything other than `fields`/`select`. That changes the response shape - `hydra:member` becomes aggregate rows instead of records.

### Field projection with selectFields and ignoreFields

Body-level allow/deny lists for the response shape. Lighter than aggregations - they don't flip the query into aggregate mode, they just shape what each `hydra:member` record contains.

```jsonc
{
  "logic": "AND",
  "filters": [ { "field": "status.itemValue", "operator": "eq", "value": "Open" } ],
  "__selectFields": ["id", "uuid", "name", "severity", "status", "createDate"]
}
```

```jsonc
{
  "logic": "AND",
  "filters": [ { "field": "createDate", "operator": "gte", "value": 1735689600, "type": "datetime" } ],
  "__ignoreFields": ["createDate", "createUser", "modifyDate", "modifyUser", "@settings"]
}
```

Use one or the other, not both. Common for **bulk export** (drop audit/ownership fields) and **bulk dashboards** (only fetch what the tile renders). Equivalent to the URL-side `$fields` projection on `GET /api/3/<resource>` but available on the body grammar where you also have OR / nested filters / aggregates.

### Top-level search URL parameter

Available on **both** `GET /api/3/<resource>` and `POST /api/query/<resource>`:

```
GET  /api/3/workflows?$search=fortinet
POST /api/query/workflows?$search=fortinet  + body filters
```

- Case-insensitive substring across the entity's "searchable fields" (per-entity set).
- Tokenized when multi-word.
- AND-combinable with body filters / URL filters.
- No min-length gate (`$search=a` happily matches).
- **Top-level only.** Putting `{"$search": "x"}` inside the body's `filters[]` is silently ignored.

### Elasticsearch global search endpoint

Different beast. Use for "global search bar" UX; for deterministic per-entity filtering use `/api/query` instead.

```jsonc
{
  "q": "fortinet phishing",         // **min 3 chars** enforced
  "index": ["alerts", "incidents"], // required, non-empty
  "size": 30, "offset": 0,
  "searchType": "_default",
  "modifyDateGte": 0, "modifyDateLte": 0
}
```

- Multi-index in one call.
- Team / RBAC scoped automatically (joins `accessibleTeamIris`).
- 3-character minimum enforced server-side.
- Some 7.6.x builds return 500 here with a server-side TypeError; verify on your appliance before relying on it.

### Persisted queries

Save a body via `POST /api/3/query_objects`, then invoke via `POST /api/query/<resource>/<queryId>`. Useful as a permission-grantable replacement for hand-shipping query bodies in client code. CRUD lives at `/api/3/queries`, `/api/3/system_queries`, `/api/3/user_queries`.

## Audit gateway quirks

`POST /api/gateway/audit/activities` is the workhorse for SIEM-style log pulls. It has nine traps worth knowing about up-front.

1. **Slice pagination, no totals.** The response has no `totalElements` / `totalPages` / `last` (intentional - the repository skips `COUNT(*)` for performance). Detect end-of-data via empty `content` or `content.length < limit`. For totals, call the sibling `/count` endpoint.
2. **Default `limit` is 10 if you misname the param.** Conventions like `size`, `pageSize`, `max` are silently dropped and the server applies its default of 10. Only `limit` works.
3. **`filterParams: { ... }` wrapper is silently ignored.** Filters must be at the top level of the body; anything nested under `filterParams` is dropped.
4. **Arrays don't work for any filter.** `{"operation": ["Login Success"]}` (single-element array) silently no-ops. `{"operation": ["A", "B"]}` returns 400. To get multiple ops server-side, make multiple calls and merge.
5. **`user` is not filterable, only `userId`.** `{"user": "Jane Doe"}` is silently ignored. `{"userId": "jdoe"}` works.
6. **`search` is brittle.** `{"search": "Login"}` returned 0 hits even with many "Login" titles in the data. Probably searches a specific subset of fields with prefix-only matching. Don't rely on it.
7. **No server-side sort control.** Records arrive `id DESC` (newest first). No `sort` param honored. Sort client-side if you need anything else.
8. **`displayName` arrives dirty.** Some records have extra whitespace, embedded UUIDs, even unrelated text from other fields. Sanitize on read.
9. **JWT lifetime is short.** Default ~30 min; long-running syncs need to re-auth on 401 or use a service-account token with extended TTL.

The 45-value `operation` enum is in the `AuditOperation` schema; fetch it dynamically from `GET /api/gateway/audit/operations`.

## Workflows & triggers

Run control lives under `/api/wf/*`. The endpoints below cover the most common control flows; less-used ones (`historical-workflows/*`, `expressions/*`, `dynamic-variable/*`) are tracked as a future expansion.

- `POST /api/wf/api/workflows/{pk}/start/` - manually queue.
- `POST /api/wf/api/workflows/{pk}/resume/` - resume a `paused` run. **Not for `awaiting`** - that uses manual-input PUT.
- `POST /api/wf/api/workflows/{pk}/retry/` - retry a failed run from the failed step.
- `POST /api/wf/api/workflows/{pk}/approval/` - approval-step shortcut.

**Decoy alert:** `POST /api/wf/api/workflows/{pk}/wfinput_resume/` exists and looks canonical, but the actual resume path for `awaiting` runs is **`PUT /api/wf/api/manual-wf-input/{pk}/`** with body `{workflow: <int_pk>, input: <dict>, type, step_id}`. Don't use `wfinput_resume`.

### Triggers

Three ways to fire a playbook from outside:

- **`POST /api/triggers/1/{name}`** - hits a Custom API Endpoint trigger (named via the trigger config). Allows alternate auth (Basic / no-auth) for external webhooks, by design - keeps the core API token-locked while letting webhook senders use simpler auth.
- **`POST /api/triggers/1/deferred/{name}`** - same as above but async (returns 202).
- **`POST /api/triggers/1/notrigger/{workflowId}`** - direct execution of a workflow by UUID, bypassing trigger conditions. Useful for testing.

The notifier service has additional fan-out via STOMP-over-WebSocket at `/websocket/` (server pushes workflow updates on `/topic/workflows/`). No REST surface; out of scope here.

### Triggering a playbook with an API key and tracking the task

Worked end-to-end flow against a Custom API Endpoint trigger: fire the playbook, capture the `task_id`, poll the workflow log until it reaches a terminal state, then fetch full execution details. Same pattern works for `deferred/` (async) and `notrigger/<workflowId>` - only the trigger URL changes.

**1. Fire the trigger.** `POST /api/triggers/1/<endpoint-name>` with the body the playbook expects. Auth header is `Authorization: API-KEY <key>` (literal space, not a colon). The response always contains a `task_id` - that is the handle you track, not the workflow IRI.

```python
import requests

BASE_URL = "https://fortisoar.example.com"
HEADERS = {
    "Authorization": f"API-KEY {API_KEY}",
    "Content-Type": "application/json",
}

resp = requests.post(
    f"{BASE_URL}/api/triggers/1/lookup_ip",
    headers=HEADERS,
    json={"value": "1.1.1.2"},
    verify=False,
)
resp.raise_for_status()
task_id = resp.json().get("task_id") or resp.json()["data"]["task_id"]
```

The `task_id` field sometimes sits at the top level and sometimes inside `data` depending on the trigger flavor - check both. Synchronous triggers return 200; `deferred/` returns 202 with the same envelope.

**2. Poll the workflow log by `task_id`.** The workflows endpoint indexes runs by `task_id` and returns the parent run when filtered with `parent_wf__isnull=True` (skips child sub-workflows). Order by `-modified` and take the first hit.

```python
url = (
    f"{BASE_URL}/api/wf/api/workflows/"
    f"?format=json&limit=1&offset=0&ordering=-modified"
    f"&task_id={task_id}&parent_wf__isnull=True"
)
log = requests.get(url, headers=HEADERS, verify=False).json()["hydra:member"][0]
status = log["status"]   # pending | running | finished | failed | terminated | skipped
workflow_id = log["@id"].rstrip("/").split("/")[-1]
```

Terminal states are **`finished`**, **`failed`**, **`terminated`**, **`skipped`**. Anything else (`pending`, `running`, `awaiting`, ...) means keep polling. An empty `hydra:member` array right after trigger is normal - the log row is written on first executor pickup, not on trigger receipt.

**3. Fetch full execution details.** Once terminal, hit the workflow record directly:

```python
details = requests.get(
    f"{BASE_URL}/api/wf/api/workflows/{workflow_id}/?format=json",
    headers=HEADERS, verify=False,
).json()
```

- **`details["result"]`** - the playbook's final output (the output of the last executed step). This is what 90% of callers want.
- **`details["name"]`** - playbook name.
- **`details["status"]`** - same terminal status as the log row.
- **Per-step outputs** - the workflow record also carries a step-execution array (field name varies by FortiSOAR version); each entry has a step name + its output. Useful when you need an intermediate step's value rather than the last one. Inspect `details.keys()` on your appliance to confirm the field name before relying on it.

If the last step produced no output, `result` is `null` even on `status: finished` - that's expected, not an error.

**Gotchas observed in practice:**

- **Poll interval.** 5 s is a sensible floor; the executor batches log writes. Tighter polling just multiplies the request count without buying any latency.
- **No `task_id` in response.** Usually means the trigger name is wrong (404 was masked by a redirect) or the playbook is inactive. The endpoint returns 200 with an empty body in some edge cases - always check before subscripting.
- **`parent_wf__isnull=True` is required** for playbooks that fan out via `Execute Sub Playbook`. Without it the first match may be a child run that finishes before the parent.
- **API-KEY vs Bearer.** API-KEY tokens don't expire, so they're the right choice for long-running tracker scripts; JWTs typically die after ~30 minutes mid-poll.

## Imports & exports

There are **two import paths** with different semantics; the wrong choice silently fails.

| Endpoint | Body | Behavior |
|---|---|---|
| `POST /api/3/workflow_collections` | unwrapped collection (`{name, description, visible, uuid, workflows: [...]}`) | strict create. **409 `UniqueConstraintViolationException`** on UUID collision. |
| `POST /api/3/import_jobs` | export-style envelope (`{type, data, macros, exported_tags}`) | **does not import the JSON inline** - see gotcha below. |

### The import_jobs gotcha

The import-job record has fields `file`, `status`, `options`, `type` - and **no `data` field**. The server's request decoder silently drops unknown keys and accepts your payload's outer `type` (e.g. `"workflow_collections"`), overriding the expected `"Import Wizard"` value. Result: 200 OK, no actual import.

**Real flow:**

1. `POST /api/3/files/` (multipart) - upload the JSON blob.
2. `POST /api/3/import_jobs` with `{file: "/api/3/files/<uuid>", type: "Import Wizard", options: {...}}`.
3. The import worker picks up the job and applies the file.

### Default mergeType is merge_append

A naive re-POST to `import_jobs` returns 200 but **silently skips** any playbook whose UUID *or* `(name, collection)` matches an existing record. For dev-loop overwrite semantics, attach explicit options:

```json
{
  "type": "Import Wizard",
  "file": "/api/3/files/<uuid>",
  "options": {
    "playbooks": {
      "include": true,
      "values": [
        {"uuid": "<col-uuid>", "name": "<col-name>",
         "include": true, "mergeType": "merge_replace",
         "includeSchedules": true}
      ]
    }
  }
}
```

| `mergeType` | Collection-level | Workflow-level |
|---|---|---|
| `rename` | suffix ` (1)`, ` (2)`... until unique; new UUID | re-rolls UUIDs |
| `replace` | DELETE + insert | (whole collection replaced) |
| `merge_replace` | keep collection, replace workflows | UUID-or-name match -> DELETE -> insert new |
| `merge_append` (default) | keep collection, add new | UUID-or-name match -> skip incoming |

### Entity uniqueness constraints

| Entity | Constraint | Notes |
|---|---|---|
| `WorkflowCollection.name` | `nullable=false`, **`unique=true`** instance-wide | rename or DELETE the existing one before re-import. |
| `Workflow` | `UniqueConstraint(columns={"name", "collection"})` | unique **per collection**, not globally. |
| `Workflow.aliasName` | `nullable=true`, no unique constraint | safe to emit `null`. |
| `WorkflowStep.name` | `nullable=false`, length 255 | required. |
| `WorkflowRoute.sourceStep` / `targetStep` | FK `nullable=false`, `onDelete="CASCADE"` | both required; deleting a step cascades its routes. |

### Cross-collection UUID collision

If a workflow UUID matches one already in a *different* collection, FortiSOAR re-rolls a fresh UUID for the workflow **and all its steps**. Deterministic UUIDs are stable **within a collection** only, not portable across.
"""


SPEC = {
    "openapi": "3.1.0",
    "info": {
        "title": "FortiSOAR API",
        "version": "0.1.0",
        "summary": "Hand-shaped subset of the FortiSOAR REST API.",
        "description": REFERENCE_PROSE,
    },
    "servers": [
        {"url": "https://{host}", "variables": {"host": {"default": "fortisoar.example.com"}}},
    ],
    "security": [{"apiKeyAuth": []}, {"bearerJwt": []}],
    "tags": [{"name": n, "description": d} for n, d in TAG_DESCRIPTIONS.items()],
    "x-tagGroups": TAG_GROUPS,
    "paths": PATHS,
    "components": {
        "securitySchemes": {
            "apiKeyAuth": {
                "type": "apiKey", "in": "header", "name": "Authorization",
                "description": "Format: `API-KEY <your_key>` (note the literal space).",
            },
            "bearerJwt": {
                "type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                "description": "Obtain via `POST /auth/authenticate`.",
            },
        },
        "schemas": SCHEMAS,
    },
}


# ---------------------------------------------------------------------------
# Enrichment - ensure every op has a request example + a response example
# ---------------------------------------------------------------------------

GENERIC_ERROR = {
    "@context": "/api/3/contexts/Error",
    "@type": "Error",
    "hydra:title": "An error occurred",
    "hydra:description": "Validation failed.",
}


def _ensure_examples(spec):
    """Walk every operation and stamp in examples where they're missing.

    Policy:
    - **Request bodies**: synthesize a best-effort example from the schema.
      A schema'd shape is honest signal; an empty schema yields `{}`.
    - **2xx responses**: only stamp when we can derive a real shape from a
      declared `schema` (a `$ref` or inline `properties`). When we have no
      schema and no curated example, leave the response example unset — we
      don't fabricate `@context`/Hydra envelopes, because that misleads readers
      into thinking we've verified the wire shape. Live captures (from
      `_apply_live_observations`) fill these in later when available.
    - **4xx/5xx**: stamp the generic Hydra error envelope (the shape is
      uniform across FortiSOAR error responses).
    """
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method in {"parameters"}:
                continue
            # request body
            rb = op.get("requestBody")
            if rb:
                for mt, content in rb.get("content", {}).items():
                    if "example" not in content and "examples" not in content:
                        if mt == "multipart/form-data":
                            continue
                        example = _example_from_schema(content.get("schema"), spec)
                        if example is not None:
                            content["example"] = example
            # responses
            for code, resp in op.get("responses", {}).items():
                content = resp.get("content")
                if not content:
                    continue
                for mt, ct in content.items():
                    if mt != "application/json":
                        continue
                    if "example" in ct or "examples" in ct:
                        continue
                    if code.startswith("2"):
                        schema = ct.get("schema")
                        if not schema:
                            continue
                        example = _example_from_schema(schema, spec)
                        if example is not None:
                            ct["example"] = example
                    elif code.startswith(("4", "5")):
                        ct["example"] = GENERIC_ERROR


def _example_from_schema(schema, spec):
    """Best-effort example from a (possibly $ref'd) schema. Returns None
    when the schema carries no shape signal we can honestly render."""
    if not schema:
        return None
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        s = spec["components"]["schemas"].get(name, {})
        return _example_from_schema(s, spec)
    if "allOf" in schema:
        merged = {}
        for part in schema["allOf"]:
            ex = _example_from_schema(part, spec)
            if isinstance(ex, dict):
                merged.update(ex)
        return merged or None
    t = schema.get("type")
    if "example" in schema:
        return schema["example"]
    if t == "array":
        return [_example_from_schema(schema.get("items", {}), spec)]
    if t == "object" or "properties" in schema:
        out = {}
        for k, v in (schema.get("properties") or {}).items():
            if isinstance(v, dict):
                if "example" in v:
                    out[k] = v["example"]
                elif "default" in v:
                    out[k] = v["default"]
                elif "enum" in v:
                    out[k] = v["enum"][0]
                elif "$ref" in v:
                    out[k] = _example_from_schema(v, spec)
                else:
                    vt = v.get("type")
                    if isinstance(vt, list):
                        vt = next((x for x in vt if x != "null"), vt[0])
                    out[k] = {"string": "example", "integer": 0, "number": 0,
                               "boolean": False, "array": [], "object": {}}.get(vt, None)
        return out
    return None


# ---------------------------------------------------------------------------
# Hand-curated examples for ops we don't (and shouldn't) hit during the
# read-only verifier sweep. Real captured data overrides these in
# _merge_verification - this is the floor, not the ceiling.
# ---------------------------------------------------------------------------

_UUID = "f3a2c1de-9b40-4ed3-9f7c-2e1d8a5b3c91"
_UUID2 = "a7e54b80-1234-4cab-8b2f-9d11f3b6a2c4"
_PB_UUID = "c0d3e8a1-7b2f-4a91-b85e-7d2e1f3a4b56"
_FILE_UUID = "1f9a3c4d-5e6b-4789-a012-3b4c5d6e7f80"

CURATED_EXAMPLES = {
    ("POST", "/api/3/logout"): {"response": {"204": None}},

    ("GET", "/api/auth/cluster/health"): {"response": {"200": [
        {
            "node": "fsr-1",
            "status": "Healthy",
            "role": "Primary",
            "connectivity": {"primary": "ok", "secondary": "ok"},
            "services": {
                "messageQueue": "running",
                "appServer": "running",
                "search": "running",
                "workflow": "running",
                "integrations": "running",
                "auth": "running",
            },
            "cpu": {"usage_pct": 18.4, "load_avg_1m": 0.62},
            "memory": {"total_mb": 32768, "used_mb": 18204, "used_pct": 55.6},
            "disk": [
                {"mountpoint": "/", "used_pct": 41.2, "free_gb": 142.8},
                {"mountpoint": "/var", "used_pct": 67.5, "free_gb": 51.4},
            ],
            "replication_stat": {"state": "Streaming", "lag_seconds": 0},
            "workflow": {"queue_depth": 0, "active_runs": 3, "failed_24h": 1},
            "lastCheckedAt": 1736380800,
        },
        "... <2 more nodes truncated>",
    ]}},

    ("GET", "/api/auth/license"): {"response": {"200": {
        "uuid": "fsr-license-9876",
        "serialNumber": "FSRVMS0000000001",
        "edition": "Enterprise", "tier": "Premium",
        "issueDate": 1727740800, "expiryDate": 1759276800,
        "users": {"licensed": 25, "active": 14},
        "agents": {"licensed": 50, "active": 12},
        "features": ["MSSP", "SOAR", "TI", "SOC", "AGENTS"],
    }}},

    ("DELETE", "/api/3/alerts/{uuid}"): {"response": {"204": None}},

    # Concrete /api/3/alerts ops. Bodies use the placeholder strings the
    # verifier rewrites at runtime (`/api/3/picklists/<role>-uuid`); the
    # verifier substitutes a real harvested IRI before sending.
    ("POST", "/api/3/alerts"): {
        "request": {
            "name": "Phishing email - finance",
            "source": "Proofpoint",
            "severity": "/api/3/picklists/high-uuid",
            "status":   "/api/3/picklists/open-uuid",
        },
        "response": {"201": {
            "@context": "/api/3/contexts/Alert",
            "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
            "uuid": _UUID, "name": "Phishing email - finance",
            "source": "Proofpoint",
            "severity": "/api/3/picklists/high-uuid",
            "status":   "/api/3/picklists/open-uuid",
            "createDate": 1736380800, "modifyDate": 1736380800,
        }},
    },
    ("PUT", "/api/3/alerts/{uuid}"): {
        "request": {
            "@id": f"/api/3/alerts/{_UUID}",
            "status": "/api/3/picklists/closed-uuid",
        },
        "response": {"200": {
            "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert", "uuid": _UUID,
            "status": "/api/3/picklists/closed-uuid",
            "modifyDate": 1736384400,
        }},
    },

    ("POST", "/api/3/{collection}"): {
        "request": {"name": "Phishing email - finance", "source": "Proofpoint",
                    "severity": "/api/3/picklists/high-uuid",
                    "status": "/api/3/picklists/open-uuid"},
        "response": {"201": {
            "@context": "/api/3/contexts/Alert",
            "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
            "uuid": _UUID, "id": 12847,
            "name": "Phishing email - finance", "source": "Proofpoint",
            "severity": "/api/3/picklists/97e9bc03-5a4c-43c6-b3a3-47422b42d288",
            "status": "/api/3/picklists/57111d6e-09a9-4d9e-93d4-cf6a8b9d77e2",
            "createDate": 1736380800, "modifyDate": 1736380800,
            "createUser": "/api/3/people/bcb46d5a-0ad8-4480-ac68-9ebc28502a30",
        }},
    },

    ("PUT", "/api/3/{collection}/{uuid}"): {
        "request": {"@id": f"/api/3/alerts/{_UUID}", "status": "/api/3/picklists/closed-uuid"},
        "response": {"200": {"@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
                              "uuid": _UUID, "status": "/api/3/picklists/closed-uuid",
                              "modifyDate": 1736384400}},
    },
    ("DELETE", "/api/3/{collection}/{uuid}"): {"response": {"204": None}},

    # Bulk ops - same envelope pattern across insert/update/delete/upsert.
    ("POST", "/api/3/insert/{moduleType}"): {
        "request": [
            {"name": "alert-001", "source": "Splunk", "sourceId": "spl-1001"},
            {"name": "alert-002", "source": "Splunk", "sourceId": "spl-1002"},
        ],
        "response": {"200": {
            "@context": "/api/3/contexts/BulkResult", "@type": "BulkResult",
            "totalCount": 2, "successCount": 2, "failureCount": 0,
            "results": [
                {"status": "success", "uuid": _UUID, "@id": f"/api/3/alerts/{_UUID}"},
                {"status": "success", "uuid": _UUID2, "@id": f"/api/3/alerts/{_UUID2}"},
            ],
        }},
    },
    ("PUT", "/api/3/update/{moduleType}"): {
        "request": [{"@id": f"/api/3/alerts/{_UUID}", "severity": "/api/3/picklists/high-uuid"}],
        "response": {"200": {"totalCount": 1, "successCount": 1, "failureCount": 0,
                              "results": [{"status": "success", "uuid": _UUID}]}},
    },
    ("DELETE", "/api/3/delete/{moduleType}"): {
        "request": [f"/api/3/alerts/{_UUID}", f"/api/3/alerts/{_UUID2}"],
        "response": {"200": {"totalCount": 2, "successCount": 2, "failureCount": 0}},
    },
    ("POST", "/api/3/upsert/{moduleType}"): {
        "request": [{"sourceId": "spl-1001", "name": "alert-001-updated", "source": "Splunk"}],
        "response": {"200": {"totalCount": 1, "successCount": 1, "failureCount": 0,
                              "results": [{"status": "updated", "uuid": _UUID}]}},
    },
    ("POST", "/api/3/bulkupsert/{moduleType}"): {
        "request": [{"sourceId": "spl-1001", "name": "alert-001"},
                     {"sourceId": "spl-1002", "name": "alert-002"}],
        "response": {"200": {"totalCount": 2, "successCount": 2, "failureCount": 0,
                              "results": [{"status": "created", "uuid": _UUID},
                                          {"status": "updated", "uuid": _UUID2}]}},
    },
    ("POST", "/api/ingest-feeds/indicators"): {
        "request": [
            {"value": "192.0.2.50", "type": "IP Address", "tlp": "WHITE",
             "source": "FortiGuard", "confidence": 80, "reputation": "Malicious"},
            {"value": "evil.example.com", "type": "Domain", "tlp": "AMBER",
             "source": "FortiGuard", "confidence": 90},
        ],
        "response": {"200": {"totalCount": 2, "successCount": 2, "failureCount": 0,
                              "skipTriggers": True}},
    },
    ("POST", "/api/insert-feeds/{recordType}"): {
        "request": [{"name": "feed-record-1", "source": "MISP"}],
        "response": {"200": {"totalCount": 1, "successCount": 1, "failureCount": 0,
                              "skipTriggers": True}},
    },

    ("POST", "/api/search"): {
        "request": {"q": "fortinet phishing", "index": ["alerts", "incidents"], "size": 30},
        "response": {"200": {
            "took": 142, "timed_out": False,
            "hits": {"total": 87, "max_score": 6.42, "hits": [
                {"_index": "alerts", "_id": _UUID, "_score": 6.42,
                 "_source": {"name": "Fortinet phishing - exec impersonation",
                              "source": "Proofpoint", "severity": "High",
                              "modifyDate": 1736380800}},
                {"_index": "incidents", "_id": _UUID2, "_score": 5.81,
                 "_source": {"name": "INC-204 phishing campaign",
                              "status": "Investigating", "modifyDate": 1736294400}},
            ]},
        }},
    },

    ("DELETE", "/api/gateway/audit/activities"): {"response": {"200": {"deleted": 1240}}},

    ("GET", "/api/gateway/audit/activities/ttl"): {"response": {"200": {
        "ttlEnabled": True, "ttlDays": 90, "lastPurgeDate": 1736294400, "lastPurgeCount": 8421,
    }}},
    ("POST", "/api/gateway/audit/activities/ttl"): {
        "request": {"ttlDays": 180},
        "response": {"200": {"ttlEnabled": True, "ttlDays": 180}},
    },
    ("DELETE", "/api/gateway/audit/activities/ttl"): {"response": {"200": {"ttlEnabled": False}}},

    # Workflow run-control - all return the same envelope per WF_DJANGO_API.
    ("POST", "/api/wf/api/workflows/{pk}/start/"): {
        "request": {"data": {"alert": f"/api/3/alerts/{_UUID}"}},
        "response": {"200": {"status": "queued", "workflow": _PB_UUID,
                              "executionId": "exec-3a8f2c", "queuedAt": 1736380800}},
    },
    ("POST", "/api/wf/api/workflows/{pk}/resume/"): {
        "response": {"200": {"status": "resumed", "workflow": _PB_UUID, "fromStep": "step-decision-2"}},
    },
    ("POST", "/api/wf/api/workflows/{pk}/retry/"): {
        "response": {"200": {"status": "retrying", "workflow": _PB_UUID, "fromFailedStep": "step-http-3"}},
    },
    ("POST", "/api/wf/api/workflows/{pk}/approval/"): {
        "request": {"decision": "approve", "comment": "Verified false positive."},
        "response": {"200": {"status": "approved", "workflow": _PB_UUID, "decidedBy": "csadmin"}},
    },

    ("POST", "/api/triggers/1/{name}"): {
        "request": {"alert": {"name": "ext-webhook-001", "source": "Webhook"}},
        "response": {"200": {"status": "ok", "workflow": _PB_UUID, "executionId": "exec-7b1e94"}},
    },
    ("POST", "/api/triggers/1/deferred/{name}"): {
        "request": {"alert": {"name": "ext-webhook-002"}},
        "response": {"202": {"status": "accepted", "executionId": "exec-9d2f17", "deferred": True}},
    },
    ("POST", "/api/triggers/1/notrigger/{workflowId}"): {
        "request": {"data": {"alert": f"/api/3/alerts/{_UUID}"}},
        "response": {"200": {"status": "ok", "workflow": _PB_UUID, "executionId": "exec-2c8a06"}},
    },

    ("POST", "/api/integration/configuration/"): {
        "request": {"connector": "fortinet-fortigate", "name": "fgt-east-prod",
                     "config": {"hostname": "fgt-east.example.com", "port": 443,
                                "verify_ssl": True, "api_key": "<api_key>"}},
        "response": {"201": {"@id": f"/api/3/connector_configurations/{_UUID}",
                              "uuid": _UUID, "connector": "fortinet-fortigate",
                              "name": "fgt-east-prod", "status": "Available"}},
    },
    ("POST", "/api/integration/execute/"): {
        "request": {"connector": "fortinet-fortigate", "operation": "block_ip",
                     "config": "fgt-east-prod", "params": {"ip": "192.0.2.50", "duration": 3600}},
        "response": {"200": {"status": "Success", "data": {"blocked": True, "ruleId": "deny-3409",
                              "appliedAt": 1736380800}, "operation": "block_ip"}},
    },
    ("POST", "/api/integration/connectors/healthcheck/"): {
        "request": {"name": "fortinet-fortigate", "version": "3.2.1",
                     "config": {"hostname": "fgt-east.example.com"}},
        "response": {"200": {"status": "Available", "checkedAt": 1736380800,
                              "responseMs": 184, "version": "3.2.1"}},
    },

    ("GET", "/api/3/picklists/{uuid}"): {"response": {"200": {
        "@context": "/api/3/contexts/Picklist",
        "@id": f"/api/3/picklists/{_UUID}", "@type": "Picklist",
        "uuid": _UUID, "itemValue": "High", "orderIndex": 2,
        "color": "#ef5350", "icon": "fa-arrow-up",
        "listName": "/api/3/picklist_names/97e9bc03-5a4c-43c6-b3a3-47422b42d288",
    }}},
    ("GET", "/api/3/picklist_names/{uuid}"): {"response": {"200": {
        "@context": "/api/3/contexts/PicklistName",
        "@id": f"/api/3/picklist_names/{_UUID}", "@type": "PicklistName",
        "uuid": _UUID, "name": "AlertSeverity", "displayName": "Alert Severity",
        "picklists": [
            f"/api/3/picklists/{_UUID2}",
            "/api/3/picklists/3b0f2a4d-1c8e-4b5a-9d6f-7e2b3c1a4d5e",
        ],
    }}},

    ("POST", "/api/3/files"): {"response": {"201": {
        "@context": "/api/3/contexts/File", "@id": f"/api/3/files/{_FILE_UUID}",
        "@type": "File", "uuid": _FILE_UUID, "name": "evidence.pcap",
        "size": 102842, "mimeType": "application/vnd.tcpdump.pcap",
        "createDate": 1736380800,
        "createUser": "/api/3/people/bcb46d5a-0ad8-4480-ac68-9ebc28502a30",
    }}},

    ("POST", "/api/3/api_keys"): {
        "request": {"name": "ci-pipeline-prod", "expiresOn": 1767225600,
                     "appliance": "/api/3/appliances/432ba9fe-0955-4379-9177-68b0d87e8caf"},
        "response": {"201": {"@id": f"/api/3/api_keys/{_UUID}", "uuid": _UUID,
                              "name": "ci-pipeline-prod",
                              "key": "REDACTED-ONLY-SHOWN-ONCE-ON-CREATE",  # pragma: allowlist secret
                              "expiresOn": 1767225600, "createDate": 1736380800}},
    },
    ("POST", "/api/3/roles"): {
        "request": {"name": "Tier1 Analyst", "description": "Read all, write alerts/incidents.",
                     "permissions": {"alerts": {"read": True, "create": True, "update": True, "delete": False}}},
        "response": {"201": {"@id": f"/api/3/roles/{_UUID}", "uuid": _UUID, "name": "Tier1 Analyst"}},
    },
    ("POST", "/api/3/teams"): {
        "request": {"name": "SOC East", "description": "East-coast SOC team",
                     "members": ["/api/3/people/bcb46d5a-0ad8-4480-ac68-9ebc28502a30"]},
        "response": {"201": {"@id": f"/api/3/teams/{_UUID}", "uuid": _UUID, "name": "SOC East"}},
    },

    ("POST", "/api/3/import_jobs"): {
        "response": {"200": {
            "@context": "/api/3/contexts/ImportJob",
            "@id": f"/api/3/import_jobs/{_UUID}", "@type": "ImportJob",
            "uuid": _UUID, "type": "Import Wizard", "status": "Queued",
            "file": f"/api/3/files/{_FILE_UUID}", "createDate": 1736380800,
            "options": {"playbooks": {"include": True, "values": [
                {"uuid": _PB_UUID, "name": "Phishing Response", "include": True,
                 "mergeType": "merge_replace", "includeSchedules": True}]}},
        }},
    },
    ("POST", "/api/3/export_jobs"): {
        "request": {"type": "workflow_collections", "data": [{"uuid": _PB_UUID}]},
        "response": {"200": {"@id": f"/api/3/export_jobs/{_UUID}", "uuid": _UUID,
                              "status": "Queued", "createDate": 1736380800}},
    },

    ("POST", "/api/3/cache_util"): {
        "request": {"action": "invalidate", "scope": "all"},
        "response": {"200": {"status": "ok", "invalidated": 14, "at": 1736380800}},
    },
}


CROSS_LINKS = {
    # Records / generic CRUD - point at concepts (IRI / picklist rules) and pagination.
    "/api/3/{collection}": "[Concepts](#description/concepts) - [Pagination & response shape](#description/pagination-response-shape)",
    "/api/3/{collection}/{uuid}": "[Concepts](#description/concepts)",
    "/api/3/alerts": "[Concepts](#description/concepts) - [Pagination & response shape](#description/pagination-response-shape)",
    "/api/3/alerts/{uuid}": "[Concepts](#description/concepts)",
    # Bulk
    "/api/3/insert/{moduleType}": "[Concepts](#description/concepts) (trigger-bypass semantics)",
    "/api/3/update/{moduleType}": "[Concepts](#description/concepts)",
    "/api/3/delete/{moduleType}": "[Concepts](#description/concepts)",
    "/api/3/upsert/{moduleType}": "[Concepts](#description/concepts)",
    "/api/3/bulkupsert/{moduleType}": "[Concepts](#description/concepts)",
    "/api/ingest-feeds/indicators": "[Concepts](#description/concepts) (trigger-bypass)",
    "/api/insert-feeds/{recordType}": "[Concepts](#description/concepts) (trigger-bypass)",
    # Query
    "/api/query/{collection}": "[Query reference](#description/query-reference)",
    "/api/query/{collection}/{queryId}": "[Persisted queries](#description/query-reference) (Query reference -> Persisted queries)",
    "/api/search": "[Query reference](#description/query-reference) (`/api/search` section)",
    # Audit
    "/api/gateway/audit/activities": "[Audit gateway quirks](#description/audit-gateway-quirks)",
    "/api/gateway/audit/activities/count": "[Audit gateway quirks](#description/audit-gateway-quirks)",
    "/api/gateway/audit/activities/{auditId}": "[Audit gateway quirks](#description/audit-gateway-quirks)",
    "/api/gateway/audit/operations": "[Audit gateway quirks](#description/audit-gateway-quirks)",
    "/api/gateway/audit/activities/ttl": "[Audit gateway quirks](#description/audit-gateway-quirks)",
    # Workflows
    "/api/wf/api/workflows/": "[Workflows & triggers](#description/workflows-triggers) (filter by `task_id` to track a triggered run)",
    "/api/wf/api/workflows/{pk}/": "[Triggering a playbook with an API key and tracking the task](#description/triggering-a-playbook-with-an-api-key-and-tracking-the-task) (per-run detail with `result` map)",
    "/api/wf/api/workflows/count": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/wf/api/workflows/{pk}/start/": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/wf/api/workflows/{pk}/resume/": "[Workflows & triggers](#description/workflows-triggers) (decoy alert: not for `awaiting` runs)",
    "/api/wf/api/workflows/{pk}/retry/": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/wf/api/workflows/{pk}/approval/": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/wf/api/manual-wf-input/list_wfinput/": "[Workflows & triggers](#description/workflows-triggers) (canonical resume path)",
    # Triggers
    "/api/triggers/1/{name}": "[Workflows & triggers](#description/workflows-triggers) (Triggers)",
    "/api/triggers/1/deferred/{name}": "[Workflows & triggers](#description/workflows-triggers) (Triggers)",
    "/api/triggers/1/notrigger/{workflowId}": "[Workflows & triggers](#description/workflows-triggers) (Triggers)",
    # Imports
    "/api/3/import_jobs": "[Imports & exports](#description/imports-exports)",
    "/api/3/export_jobs": "[Imports & exports](#description/imports-exports)",
    "/api/3/files": "[Imports & exports](#description/imports-exports) (file upload is step 1 of import)",
    # Auth
    "/auth/authenticate": "[Authentication](#description/authentication)",
    "/api/auth/cluster/health": "[Authentication](#description/authentication) (JWT-only on tested boxes)",
    "/api/auth/license": "[Authentication](#description/authentication)",
}


def _apply_cross_links(spec):
    for path, link in CROSS_LINKS.items():
        item = spec["paths"].get(path)
        if not item:
            continue
        for method, op in item.items():
            if method == "parameters":
                continue
            line = f"**See:** {link}\n\n"
            op["description"] = line + (op.get("description") or "")


def _apply_curated_examples(spec):
    for (method, path), payload in CURATED_EXAMPLES.items():
        op = spec["paths"].get(path, {}).get(method.lower())
        if not op:
            continue
        req = payload.get("request")
        if req is not None:
            ct = (op.get("requestBody") or {}).get("content", {}).get("application/json")
            if ct is not None:
                ct["example"] = req
        for code, ex in (payload.get("response") or {}).items():
            resp = op.get("responses", {}).get(code) or op.get("responses", {}).get(int(code))
            if not resp:
                continue
            if ex is None:
                resp.pop("content", None)
                continue
            content = resp.setdefault("content", {})
            ct = content.setdefault("application/json", {})
            ct["example"] = ex


VERIFICATION_FILE = ROOT / "build" / "curated_verification.json"

# Cap large lists in response examples so the rendered docs don't ship
# 100-item paged collections inline. Applied to top-level arrays AND to
# the well-known `hydra:member` / `content` / `data` keys.
LIST_CAP = 2
TRUNCATE_KEYS = {"hydra:member", "content", "data", "results", "items"}


def _truncate_lists(obj):
    if isinstance(obj, list):
        if len(obj) > LIST_CAP:
            return [_truncate_lists(x) for x in obj[:LIST_CAP]] + [
                f"... <{len(obj) - LIST_CAP} more items truncated>"]
        return [_truncate_lists(x) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in TRUNCATE_KEYS and isinstance(v, list) and len(v) > LIST_CAP:
                out[k] = [_truncate_lists(x) for x in v[:LIST_CAP]] + [
                    f"... <{len(v) - LIST_CAP} more items truncated>"]
            else:
                out[k] = _truncate_lists(v)
        return out
    return obj


def _merge_verification(spec):
    """If a verification.json sits next to us, prepend each op's
    description with a one-line verification badge. Lets the Scalar
    page surface live-test status without a separate UI layer.
    """
    if not VERIFICATION_FILE.exists():
        # Nothing exercised at all - mark every op as unverified.
        for path, item in spec["paths"].items():
            for method, op in item.items():
                if method == "parameters":
                    continue
                op["description"] = (
                    "**Unverified** - example data is synthetic; this op has "
                    "not been exercised against a live FortiSOAR.\n\n"
                ) + (op.get("description") or "")
                op["x-fsr-status"] = "unverified-synthetic"
        return
    data = json.loads(VERIFICATION_FILE.read_text())
    verified_at = data.get("generated_at") or _dt.date.today().isoformat()
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method == "parameters":
                continue
            key = f"{method.upper()} {path}"
            v = data["ops"].get(key)

            # Op never exercised by the verifier at all (skipped, filtered,
            # or absent from a partial run). Pure synthetic example.
            if not v or "by_auth" not in v:
                reason = (v or {}).get("skipped",
                          "verifier did not exercise this op (e.g. read-only mode skipped a mutating verb)")
                op["description"] = (
                    f"**Unverified** - {reason}. Example data below is "
                    f"synthetic.\n\n"
                ) + (op.get("description") or "")
                op["x-fsr-status"] = "unverified-skipped"
                continue

            # Op exercised but no auth mode returned 2xx - real failure
            # against the live FSR.
            any_ok = any(200 <= d["status"] < 300 for d in v["by_auth"].values())
            if not any_ok:
                badges = [f"`{l}: {d['status']}`" for l, d in v["by_auth"].items()]
                op["description"] = (
                    f"**Unverified** - last live test ({verified_at}) failed: "
                    + " - ".join(badges)
                    + ". Example data below is synthetic.\n\n"
                ) + (op.get("description") or "")
                op["x-fsr-status"] = "unverified-failing"
                op["x-fsr-verification"] = v["by_auth"]
                continue

            # If this op was already touched by `live_test.py` (its description
            # carries an "Auth coverage:" line and `x-verified-live` is set),
            # skip the verifier's badge — the live-observations source is
            # richer (real captured request + response per auth) and we don't
            # want to duplicate.
            if "x-verified-live" in op or "**Auth coverage:**" in (op.get("description") or ""):
                op["x-fsr-status"] = "verified"
                op["x-fsr-verification"] = v["by_auth"]
            else:
                badges = []
                for label, d in v["by_auth"].items():
                    ok = 200 <= d["status"] < 300
                    schema_ok = d.get("schema_ok")
                    marker = ("OK" if ok else f"{d['status']}")
                    if ok and schema_ok is False:
                        marker += " (schema drift)"
                    badges.append(f"`{label}: {marker}`")
                line = "**Live-verified** (" + " - ".join(badges) + f", {verified_at})\n\n"
                op["description"] = line + (op.get("description") or "")
                op["x-fsr-status"] = "verified"
                op["x-fsr-verification"] = v["by_auth"]

            # Replace the synthesized 2xx response example with the real
            # captured response from whichever auth mode succeeded. The
            # verifier already sanitized it.
            real_resp = None
            real_req = None
            for label in ("apikey", "jwt"):
                d = v["by_auth"].get(label)
                if d and 200 <= d.get("status", 0) < 300 and isinstance(d.get("sample_response"), (dict, list)):
                    real_resp = d["sample_response"]
                    real_req = (d.get("sent_request") or {}).get("body")
                    break
            if real_resp is not None:
                for code, resp in op.get("responses", {}).items():
                    if not str(code).startswith("2"):
                        continue
                    ct = resp.get("content", {}).get("application/json")
                    if ct is not None:
                        ct["example"] = _truncate_lists(real_resp)
                    break
            if real_req is not None:
                rb = op.get("requestBody", {}).get("content", {}).get("application/json")
                if rb is not None:
                    if isinstance(rb.get("examples"), dict):
                        # Multi-example op - add the captured one as a
                        # named entry so curated examples stay alongside.
                        rb["examples"]["live-captured"] = {
                            "summary": f"Live-captured (verified {data.get('generated_at') or _dt.date.today().isoformat()})",
                            "value": _truncate_lists(real_req),
                        }
                    else:
                        rb["example"] = _truncate_lists(real_req)

            # Surface the actually-sent query params as per-parameter
            # `example` fields so readers see real values, not just the
            # schema default.
            real_params = None
            for label in ("apikey", "jwt"):
                d = v["by_auth"].get(label)
                if d and 200 <= d.get("status", 0) < 300:
                    real_params = (d.get("sent_request") or {}).get("params") or {}
                    break
            if real_params:
                # Combine path-item-level + op-level params lists.
                for plist in (item.get("parameters") or [], op.get("parameters") or []):
                    for p in plist:
                        if p.get("in") == "query" and p.get("name") in real_params:
                            p["example"] = real_params[p["name"]]


# Implementation-detail tokens that must NOT appear in the rendered
# spec. Anything matching here is a leak per TODOS C3.5 - readers
# should see API contract only, not how the API is built or how we
# discovered it.
LEAK_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bsymfony\b",
        r"\bdoctrine\b",
        r"\bhibernate\b",
        r"\bapi\s*platform\b",
        r"\btomcat\b",
        r"\bgunicorn\b",
        r"\buwsgi\b",
        r"\bdjango\b",
        r"\bcython\b",
        r"\bphp[\s\-]?fpm\b",
        r"(?<![a-z\.])\bphp\b",                 # bare 'PHP' word, not 'phone'
        r"\bjavap\b",
        r"\bdebug:router\b",
        r"\bspring\s+(?:data|boot|conventions?)\b",
        r"\bjpa\b",
        r"\bdrf\b",
        r"\brabbit(?:mq|listener)\b",
        r"\bstdclass\b",
        r"/opt/cyops",
        r"\bcyops-(?:api|tomcat|workflow|integrations|gateway)\b",
        r"\.(?:php|class|so)\b",                 # bare file-extension refs
        r"\bjwtserviceimpl\b",
        r"\badvancedquerycontroller\b",
        r"\bplaybookconfig(?:\.php)?\b",
        r"\bimportservice\b",
        r"recon[\s\-]tarball",
        r"App\\\\(?:Query|Constants|Filter|Service|Controller)",
        r"\bcom\.cybersponse\b",
        r"\bhibernate\s+entity\b",
        r"\bphp[\s\-]?8\b",
        r"\bnginx\b",
        r"\bDAS:\d+\b",          # internal service:port leak (e.g. DAS:8443)
        # Note: bare 'das' is a legitimate audit-log `component` enum
        # value, so we don't ban it — only the service:port form.
    ]
]

# Whitelist tokens that look like leaks but legitimately appear in the
# spec (e.g. `info.json` is a connector convention, not a stack tell).
LEAK_WHITELIST_LINES = (
    "info.json",                      # connector manifest convention
    "stoplight",                      # may appear in TODOs but not output
)


def _collect_prose(spec) -> list[tuple[str, str]]:
    """Yield (location, text) pairs for every human-readable prose
    field in the spec - descriptions, summaries, titles. Skips request
    bodies, response examples, and any other captured-from-API data
    (those are what the server actually returns and are not ours to
    rewrite)."""
    out: list[tuple[str, str]] = []
    info = spec.get("info", {})
    for k in ("title", "summary", "description"):
        if isinstance(info.get(k), str):
            out.append((f"info.{k}", info[k]))
    for t in spec.get("tags", []) or []:
        if isinstance(t.get("description"), str):
            out.append((f"tags[{t.get('name','?')}].description", t["description"]))
    for path, item in (spec.get("paths") or {}).items():
        for method, op in item.items():
            if method == "parameters":
                continue
            for k in ("summary", "description"):
                if isinstance(op.get(k), str):
                    out.append((f"paths[{path}][{method}].{k}", op[k]))
            for p in op.get("parameters") or []:
                if isinstance(p.get("description"), str):
                    out.append((f"paths[{path}][{method}].parameters[{p.get('name')}].description", p["description"]))
    schemas = (spec.get("components") or {}).get("schemas") or {}
    for name, sch in schemas.items():
        if isinstance(sch.get("description"), str):
            out.append((f"components.schemas.{name}.description", sch["description"]))
        for prop_name, prop in (sch.get("properties") or {}).items():
            if isinstance(prop, dict) and isinstance(prop.get("description"), str):
                out.append((f"components.schemas.{name}.properties.{prop_name}.description", prop["description"]))
    sec = (spec.get("components") or {}).get("securitySchemes") or {}
    for name, s in sec.items():
        if isinstance(s.get("description"), str):
            out.append((f"components.securitySchemes.{name}.description", s["description"]))
    return out


def _scan_for_leaks(spec) -> list[tuple[str, str, str]]:
    """Return (location, pattern, snippet) for every leak found in the
    spec's prose fields. Empty list -> clean."""
    hits: list[tuple[str, str, str]] = []
    for loc, text in _collect_prose(spec):
        for line in text.splitlines():
            if any(w in line for w in LEAK_WHITELIST_LINES):
                continue
            for pat in LEAK_PATTERNS:
                m = pat.search(line)
                if m:
                    hits.append((loc, m.group(0), line.strip()[:160]))
                    break
    return hits


def _apply_live_observations(spec: dict) -> int:
    """Overlay captured live request/response bodies onto matching ops.

    Reads `build/live_observations.json` (written by `src/live_test.py`).
    Each op was exercised under every available auth mode; we surface:

    - The example body from a 2xx run (prefer JWT, fall back to API-KEY).
    - `x-verified-live`: list of auth modes that returned 2xx for this op.
    - A "**Auth coverage:**" line appended to the description showing the
      observed status code per auth mode, so docs flag JWT-only / API-KEY-
      only endpoints.
    """
    path = OUT.parent / "live_observations.json"
    if not path.exists():
        return 0
    try:
        obs = json.loads(path.read_text())
    except json.JSONDecodeError:
        return 0
    paths = spec["paths"]
    applied = 0
    for key, rec in obs.items():
        method, template = key.split(" ", 1)
        if template not in paths:
            continue
        op = paths[template].get(method.lower())
        if not op:
            continue
        by_auth = rec.get("by_auth") or {}
        # Pick the auth run to source examples from: any 2xx, JWT preferred.
        successful = {m: r for m, r in by_auth.items()
                      if r.get("response_status") is not None
                      and 200 <= r["response_status"] < 300}
        if not successful:
            # No mode succeeded — still record coverage so docs say so.
            op["x-verified-live"] = {m: r.get("response_status") for m, r in by_auth.items()}
            op["description"] = (op.get("description", "") + _auth_coverage_line(by_auth)).strip()
            applied += 1
            continue
        preferred = "jwt" if "jwt" in successful else next(iter(successful))
        src = successful[preferred]
        if src.get("request_body") is not None:
            rb = op.setdefault("requestBody", {})
            content = rb.setdefault("content", {}).setdefault("application/json", {})
            content["example"] = src["request_body"]
        status = str(src.get("response_status", 200))
        if src.get("response_body") is not None:
            responses = op.setdefault("responses", {})
            resp = responses.setdefault(status, {"description": "Live-captured response."})
            content = resp.setdefault("content", {}).setdefault("application/json", {})
            content["example"] = src["response_body"]
        op["x-verified-live"] = sorted(successful.keys())
        op["description"] = (op.get("description", "") + _auth_coverage_line(by_auth)).strip()
        applied += 1
    return applied


def _auth_coverage_line(by_auth: dict) -> str:
    """Format an Auth coverage markdown line summarizing per-mode statuses.

    Three states are surfaced (no emojis — labels only):
      `<auth>: OK`     — 2xx response observed.
      `<auth>: NNN`    — request reached the server and was rejected.
      `<auth>: gated`  — an upstream gate blocked us before this op was
                         reached; treat as unavailable under that auth.
    """
    if not by_auth:
        return ""
    parts = []
    for mode in sorted(by_auth):
        rec = by_auth[mode]
        label = {"jwt": "Bearer JWT", "apikey": "API-KEY"}.get(mode, mode)
        if rec.get("gated_upstream"):
            parts.append(f"`{label}: gated`")
            continue
        code = rec.get("response_status")
        if code is None:
            continue
        marker = "OK" if 200 <= code < 300 else str(code)
        parts.append(f"`{label}: {marker}`")
    if not parts:
        return ""
    return "\n\n**Auth coverage:** " + " · ".join(parts)


def main():
    _ensure_examples(SPEC)
    _apply_curated_examples(SPEC)
    _apply_cross_links(SPEC)
    # Live observations from `src/live_test.py` are the authoritative source
    # for verification badges. The older `_merge_verification` (from the
    # stateless verifier) is intentionally not invoked here — it produced a
    # parallel "Live-verified" line that duplicated the per-auth coverage
    # surfaced by `_apply_live_observations`.
    live_applied = _apply_live_observations(SPEC)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    leaks = _scan_for_leaks(SPEC)
    if leaks:
        msg = ["IMPLEMENTATION-DETAIL LEAKS in spec prose (TODOS C3.5):"]
        for loc, token, text in leaks[:20]:
            msg.append(f"  {loc}: {token!r} -> {text}")
        if len(leaks) > 20:
            msg.append(f"  ... and {len(leaks) - 20} more")
        msg.append("Fix the description / summary text in build_curated.py. "
                    "If a match is a false positive, add the substring to LEAK_WHITELIST_LINES.")
        sys.exit("\n".join(msg))
    OUT.write_text(yaml.safe_dump(SPEC, sort_keys=False, default_flow_style=False, width=120))
    op_count = sum(1 for path in PATHS.values() for k in path if k in {"get", "post", "put", "delete", "patch"})
    print(f"Wrote {OUT} ({op_count} operations across {len(PATHS)} paths, "
          f"{live_applied} live-verified)")


if __name__ == "__main__":
    main()
