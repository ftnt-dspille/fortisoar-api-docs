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

for verb, op_method, op_summary, op_desc in [
    ("insert",     "post", "Bulk insert", "Insert multiple records of the given module type in one call."),
    ("update",     "put",  "Bulk update", "Update multiple records (each with its `@id`). **Method is PUT**, not POST."),
    ("delete",     "delete", "Bulk delete", "Delete multiple records by IRI list. **Method is DELETE**, not POST."),
    ("upsert",     "post", "Upsert by natural key", "Insert-or-update keyed on the module's identifier field."),
    ("bulkupsert", "post", "Bulk upsert", "Bulk version of upsert. Note: some 7.6.x builds return 500 (server-side TypeError) when the body isn't a strict JSON array - retry with the payload wrapped as an array."),
]:
    op_def = {
        "tags": ["Bulk operations"],
        "summary": op_summary,
        "description": op_desc,
        "responses": {"200": _resp("Result envelope (per-record status).")},
    }
    if op_method != "delete":
        op_def["requestBody"] = {"required": True, "content": {"application/json": {
            "schema": {"type": "array", "items": {"type": "object"}},
        }}}
    else:
        op_def["requestBody"] = {"required": True, "content": {"application/json": {
            "schema": {"type": "array", "items": {"type": "string"}},
        }}}
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
        "description": "Runs a saved Query (created via `POST /api/3/query_objects`). Body may override pagination / sort.",
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
    "get": {"tags": ["Audit"], "summary": "Read TTL / retention setting",
            "description": "*Heads-up:* this endpoint returns 400 on plain GET on some 7.6.x builds (the gateway expects an `X-User-Authorization` HMAC header that browser clients can't easily produce). Treat as best-effort.",
            "responses": {"200": _resp("TTL config.")}},
    "post": {"tags": ["Audit"], "summary": "Set TTL", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}, "responses": {"200": _resp("Updated.")}},
    "delete": {"tags": ["Audit"], "summary": "Disable TTL", "responses": {"200": _resp("Disabled.")}},
}


# --- Workflows / triggers --------------------------------------------------

PATHS["/api/wf/api/workflows/"] = {
    "get": {"tags": ["Workflows"], "summary": "List workflows / runs",
            "responses": {"200": _resp("Collection.")}},
}

PATHS["/api/wf/api/workflows/count"] = {
    "get": {"tags": ["Workflows"], "summary": "Workflow count",
            "description": "*Heads-up:* this endpoint is **HMAC-required** (\"Could not validate HMAC fingerprint\" on Bearer or API-KEY). Reachable from server-to-server callers that compute the HMAC; not from a browser-side Test Request panel.",
            "responses": {"200": _resp("Count.", example={"count": 1667})}},
}

for action, desc in [
    ("start", "Manually queue a workflow."),
    ("resume", "Resume a paused workflow (status=`paused`; for `awaiting`, use the manual-input PUT)."),
    ("retry", "Retry a failed workflow from the failed step."),
    ("approval", "Approval-step shortcut. Body shape unverified; expected `{decision, comment}`."),
]:
    PATHS[f"/api/wf/api/workflows/{{pk}}/{action}/"] = {
        "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"}}],
        "post": {"tags": ["Workflows"], "summary": f"Workflow {action}", "description": desc,
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
             "responses": {"200": _resp("Collection of pending inputs.")}},
}

PATHS["/api/triggers/1/{name}"] = {
    "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "User-defined endpoint name from a Custom API Endpoint trigger."}],
    "post": {
        "tags": ["Triggers"],
        "summary": "Custom playbook trigger",
        "description": "Fires a playbook by its trigger's arbitrary endpoint name. May allow Basic auth or no-auth depending on trigger config (intentional, for external webhooks).",
        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {"200": _resp("Playbook output.")},
    },
}

PATHS["/api/triggers/1/deferred/{name}"] = {
    "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}],
    "post": {"tags": ["Triggers"], "summary": "Custom trigger (deferred / async)",
             "responses": {"202": _resp("Accepted.")}},
}

PATHS["/api/triggers/1/notrigger/{workflowId}"] = {
    "parameters": [{"name": "workflowId", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "post": {"tags": ["Triggers"], "summary": "Run workflow by id without firing trigger conditions",
             "responses": {"200": _resp("Run result.")}},
}


# --- Integration / connectors ---------------------------------------------

PATHS["/api/integration/connectors/"] = {
    "get": {"tags": ["Connectors"], "summary": "List installed connectors",
            "responses": {"200": _resp("Collection.")}},
}

PATHS["/api/integration/configuration/"] = {
    "get": {"tags": ["Connectors"], "summary": "List connector configurations",
            "responses": {"200": _resp("Collection.")}},
    "post": {"tags": ["Connectors"], "summary": "Create connector configuration",
             "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
             "responses": {"201": _resp("Created.")}},
}

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

PATHS["/api/integration/connectors/healthcheck/"] = {
    "post": {"tags": ["Connectors"], "summary": "Health-check a connector configuration",
             "responses": {"200": _resp("Health status.")}},
}


# --- Modules / metadata ----------------------------------------------------

PATHS["/api/3/model_metadatas"] = {
    "get": {"tags": ["Metadata"], "summary": "List module / model definitions",
            "description": "Drift-resistant alternative to a static schema snapshot.",
            "responses": {"200": _resp("Collection of ModelMetadata.")}},
}

PATHS["/api/3/picklists/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist value", "responses": {"200": _resp("Picklist record.")}},
}

PATHS["/api/3/picklist_names/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist taxonomy", "responses": {"200": _resp("Picklist name record.")}},
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

for path, tag, summary in [
    ("/api/3/api_keys", "Access management", "API keys"),
    ("/api/3/roles", "Access management", "Roles"),
    ("/api/3/teams", "Access management", "Teams"),
]:
    PATHS[path] = {
        "get": {"tags": [tag], "summary": f"List {summary.lower()}", "parameters": COMMON_QPARAMS,
                "responses": {"200": _resp("Collection.", ref="HydraCollection")}},
        "post": {"tags": [tag], "summary": f"Create {summary.lower()[:-1]}",
                 "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
                 "responses": {"201": _resp("Created.")}},
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
             "responses": {"200": _resp("Export job record.")}},
}


# --- Misc ------------------------------------------------------------------

PATHS["/api/product/feature-access"] = {
    "get": {"tags": ["System"], "summary": "Feature-flag introspection",
            "description": "License-tier-aware feature flags.", "responses": {"200": _resp("Flag map.")}},
}

PATHS["/api/3/cache_util"] = {
    "post": {"tags": ["System"], "summary": "Force cache invalidation",
             "responses": {"200": _resp("OK.")}},
}


# ---------------------------------------------------------------------------
# Spec assembly
# ---------------------------------------------------------------------------

TAG_GROUPS = [
    {"name": "Auth & system", "tags": ["Authentication", "System"]},
    {"name": "Records", "tags": ["Records (generic)", "Bulk operations", "Alerts"]},
    {"name": "Query", "tags": ["Query"]},
    {"name": "Audit", "tags": ["Audit"]},
    {"name": "Automation", "tags": ["Workflows", "Triggers", "Connectors"]},
    {"name": "Reference", "tags": ["Metadata", "Files", "Access management", "Import / export"]},
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
    "Connectors": "Connector listing, configuration CRUD, health check, and action execution. Per-operation request shape comes from each connector's `info.json` definition.",
    "Metadata": "Module + field schemas, picklist taxonomy, JSON-LD contexts, and the Hydra `ApiDocumentation` (use this to expand the curated surface).",
    "Files": "Attachment upload. Required as the first step of import-job ingestion.",
    "Access management": "API keys, roles, teams.",
    "Import / export": "Configuration import/export. Read the `import_jobs` description carefully - the inline-envelope shape is a silent no-op.",
}


A hand-shaped OpenAPI 3.1 reference for the FortiSOAR REST API.

> **Disclaimer.** This reference is a community effort and is **not exhaustive**. Coverage is the surface I use day-to-day; many operations are still missing. Operations marked with a green **`Live-verified`** badge were exercised end-to-end against a real FortiSOAR instance. Anything without that badge is documented from the API guide and DB introspection only — request/response shapes are best-effort and not guaranteed to be correct. Always validate against your own appliance before relying on it.
>
> **What the badges mean.**
> - **`Live-verified`** — the operation was called with both an API key and a JWT bearer token and returned 2xx on at least one combination. Captured (sanitized) responses are folded into the `200` example.
> - **No badge** — never executed by the verifier. Either it's a mutating operation we skip by default (DELETE, PUT, well-known mutating POSTs) or we just haven't gotten to it. Treat as documentation-only.
> - **JWT-only / API-key-only** — one auth mode returned 2xx and the other returned 401/403. Common for endpoints that enforce a single auth pathway.

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

GENERIC_RECORD = {
    "@context": "/api/3/contexts/Record",
    "@id": "/api/3/<collection>/00000000-0000-0000-0000-000000000000",
    "@type": "Record",
    "uuid": "00000000-0000-0000-0000-000000000000",
    "name": "example",
}

GENERIC_HYDRA = {
    "@context": "/api/3/contexts/Record",
    "@id": "/api/3/<collection>",
    "@type": "hydra:PagedCollection",
    "hydra:totalItems": 1,
    "hydra:itemsPerPage": 30,
    "hydra:member": [GENERIC_RECORD],
}

GENERIC_ERROR = {
    "@context": "/api/3/contexts/Error",
    "@type": "Error",
    "hydra:title": "An error occurred",
    "hydra:description": "Validation failed.",
}


def _ensure_examples(spec):
    """Walk every operation and stamp in request + response examples
    where they're not already supplied. Keeps human-curated examples;
    fills gaps with generic shapes.
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
                        content["example"] = _example_from_schema(content.get("schema"), spec)
            # responses
            for code, resp in op.get("responses", {}).items():
                content = resp.get("content")
                if not content:
                    # synthesize a JSON envelope so readers always see something
                    if code.startswith("2"):
                        resp["content"] = {"application/json": {"example":
                            GENERIC_HYDRA if method == "get" and "{" not in path.rsplit("/", 1)[-1]
                            else GENERIC_RECORD}}
                    continue
                for mt, ct in content.items():
                    if mt != "application/json":
                        continue
                    if "example" in ct or "examples" in ct:
                        continue
                    if code.startswith("2"):
                        ct["example"] = _example_from_schema(ct.get("schema"), spec)
                    elif code.startswith(("4", "5")):
                        ct["example"] = GENERIC_ERROR


def _example_from_schema(schema, spec):
    """Best-effort example from a (possibly $ref'd) schema."""
    if not schema:
        return GENERIC_RECORD
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
        return merged or GENERIC_HYDRA
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
    "/api/wf/api/workflows/": "[Workflows & triggers](#description/workflows-triggers)",
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


def main():
    _ensure_examples(SPEC)
    _apply_curated_examples(SPEC)
    _apply_cross_links(SPEC)
    _merge_verification(SPEC)
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
    print(f"Wrote {OUT} ({op_count} operations across {len(PATHS)} paths)")


if __name__ == "__main__":
    main()
