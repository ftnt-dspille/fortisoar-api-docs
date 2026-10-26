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
Live inputs, both optional: build/live_observations.json (src/live_test.py)
supplies real request/response examples; build/auth_probe/<version>.json
(src/auth_probe.py, one per measured FortiSOAR) supplies API key / JWT support.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import sys
from pathlib import Path

import yaml

from pyfsr_examples import apply_pyfsr_samples, apply_pyfsr_response_models

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "fortisoar.curated.openapi.yaml"

# Schemas auto-generated from /api/3/model_metadatas?$relationships=true via
# src/module_to_schema.py. Re-run that script to refresh.
_GENERATED_SCHEMAS = json.loads((Path(__file__).parent / "module_schemas.json").read_text())


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
            "createDate": {"type": ["number", "null"],
                           "description": "Epoch seconds (UTC), may include fractional component."},
            "modifyDate": {"type": ["number", "null"],
                           "description": "Epoch seconds (UTC), may include fractional component."},
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
                    "password": {"type": "string", "description": "The user's password."},
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

# Splice in module schemas generated from model_metadatas (Incident, Task,
# Comment, ...). These carry the full field list per module with correct
# cardinality + picklist taxonomy hints; regenerate via src/module_to_schema.py.
SCHEMAS.update(_GENERATED_SCHEMAS)

# --- Curated typed-model schemas (pyfsr response models) -------------------
# Hand-shaped from the Pydantic models pyfsr parses API responses into (the
# same classes surfaced on ops as `x-pyfsr-response-model`). These are the
# platform-owned, fixed-schema entities (agents, API keys, connectors, playbook
# runs, notifications, scheduled tasks) that the record-module generator
# doesn't cover. Curated to the most-used fields, not every internal key; the
# live wire shape is dict-compatible and tolerates extras.

SCHEMAS.update({
    "FileRecord": {
        "type": "object",
        "description": "A file upload record (`/api/3/files`). The `@id` is the IRI import/export jobs reference as their `file` field.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "File"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "filename": {"type": ["string", "null"], "description": "Original filename."},
            "mimeType": {"type": ["string", "null"]},
            "size": {"type": ["integer", "null"], "description": "Bytes."},
            "uploadDate": {"type": ["number", "null"], "description": "Epoch seconds."},
            "createUser": {"type": ["string", "object", "null"]},
            "createDate": {"type": ["number", "null"]},
            "modifyDate": {"type": ["number", "null"]},
        },
    },
    "ApiKey": {
        "type": "object",
        "description": "An API-key binding record (`/api/3/api_keys`). Binds a key user to roles and teams.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "ApiKey"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": "string", "description": "Binding display name."},
            "title": {"type": ["string", "null"]},
            "userId": {"type": ["string", "null"], "description": "IRI of the owning API-key user (`/api/3/people/<uuid>`)."},
            "roles": {"type": "array", "items": {"$ref": "#/components/schemas/IRI"},
                      "description": "Role IRIs granted to this key."},
            "teams": {"type": "array", "items": {"$ref": "#/components/schemas/IRI"},
                      "description": "Team IRIs this key belongs to."},
            "createUser": {"type": ["string", "object", "null"]},
            "createDate": {"type": ["number", "null"], "description": "Epoch seconds."},
            "modifyUser": {"type": ["string", "object", "null"]},
            "modifyDate": {"type": ["number", "null"]},
        },
    },
    "ApiKeyUser": {
        "type": "object",
        "description": "An API-key user account (`/api/auth/users` with `type=9`). The `api_key` block is returned only on create/regenerate.",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "user_type": {"type": ["integer", "null"], "description": "Account type (9 = API key)."},
            "status": {"type": ["integer", "null"], "description": "1 = active, 0 = inactive."},
            "access_type": {"type": ["string", "null"]},
            "loginid": {"type": ["string", "null"], "description": "Login id for the key user."},
            "api_key": {"$ref": "#/components/schemas/ApiKeyMaterial"},
            "bind_name": {"type": ["string", "null"]},
            "domain": {"type": ["string", "null"]},
            "is_logged_in": {"type": ["boolean", "null"]},
        },
    },
    "ApiKeyMaterial": {
        "type": "object",
        "description": "The plaintext key material, returned only on create/regenerate (never on read).",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "key": {"type": ["string", "null"], "description": "The plaintext API key. Shown once."},
            "retrievable": {"type": ["boolean", "null"], "description": "Whether the key can be re-read later."},
            "status": {"type": ["string", "null"]},
            "valid_until": {"type": ["integer", "null"], "description": "Epoch the key expires."},
            "time_remaining": {"type": ["integer", "null"], "description": "Seconds until expiry."},
        },
    },
    "Agent": {
        "type": "object",
        "description": "A remote-agent record (`/api/3/agents`). The self-agent is hardcoded at uuid `973c17df-...` on every install.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Agent"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "agentId": {"type": ["string", "null"], "description": "Runtime SME bus id (varies per appliance)."},
            "name": {"type": ["string", "null"]},
            "active": {"type": ["boolean", "null"]},
            "description": {"type": ["string", "null"]},
            "created": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
            "router": {"type": ["string", "object", "null"], "description": "Router IRI or expanded record."},
            "installerType": {"type": ["string", "null"], "description": "Picklist IRI: bash or docker."},
            "configurationHealth": {"type": ["string", "null"], "description": "Picklist IRI; `Remote Node Connected` once paired."},
        },
    },
    "FeedIngestResult": {
        "type": "object",
        "description": "Result of a trigger-bypassing feed ingest (`/api/ingest-feeds/*`).",
        "properties": {
            "status": {"type": "string", "description": "Success / failure indicator."},
            "uuids": {"type": "array", "items": {"type": "string"}, "description": "UUIDs of ingested records."},
        },
        "required": ["status"],
    },
    "BulkUpsertResult": {
        "type": "object",
        "description": "Multi-status envelope the bulk write paths return when a batch row is rejected "
                       "(a clean batch answers `201` with a plain hydra collection instead). Keys are "
                       "the wire's `success`/`failure`; pyfsr's `BulkUpsertResult` model renames them "
                       "to `succeeded`/`failed` client-side.",
        "properties": {
            "success": {"type": "array", "items": {"type": "object"},
                        "description": "The records that wrote cleanly."},
            "failure": {"type": "array", "items": {"type": "string"},
                        "description": "Raw error strings, one per rejected row."},
        },
        "required": ["success", "failure"],
    },
    "RecordWriteCollection": {
        "type": "object",
        "description": "Hydra collection of written records - the response of a clean bulk insert/update "
                       "(`POST /api/3/insert/{moduleType}`, `PUT /api/3/update/{moduleType}`). The "
                       "`hydra:member` rows carry the full field set of the module named in the path "
                       "(same shape as that module's list response).",
        "allOf": [
            {"$ref": "#/components/schemas/HydraCollection"},
            {"type": "object", "properties": {"hydra:member": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": True,
                          "description": "One written `{moduleType}` record."},
            }}},
        ],
    },
    "ModuleRecord": {
        "type": "object",
        "additionalProperties": True,
        "description": "A single written record (`POST /api/3/upsert/{moduleType}`), with the module's "
                       "full field set - same shape as one member of that module's list response.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "description": "The module type, e.g. `Alert`."},
            "uuid": {"$ref": "#/components/schemas/UUID"},
        },
    },
    "RunSummary": {
        "type": "object",
        "description": "A playbook execution summary (from `/api/wf/api/workflows/` or `historical-workflows`).",
        "properties": {
            "task_id": {"type": ["string", "null"], "description": "The run's task id - used to poll logs."},
            "name": {"type": ["string", "null"], "description": "Playbook name."},
            "status": {"type": ["string", "null"], "description": "success / failed / awaiting / running."},
            "error_message": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "pk": {"type": ["string", "null"], "description": "Primary key for the execution record."},
            "source": {"type": ["string", "null"]},
        },
    },
    "ManualInput": {
        "type": "object",
        "description": "A pending manual-input / approval step awaiting user action (`/api/wf/api/manual-wf-input/`).",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "id": {"type": ["integer", "null"]},
            "record": {"type": ["string", "null"], "description": "IRI of the record the workflow paused on."},
            "type": {"type": ["string", "null"]},
            "title": {"type": ["string", "null"]},
            "assignment_type": {"type": ["string", "null"]},
            "created": {"type": ["string", "null"]},
            "step_id": {"type": ["integer", "null"]},
            "unauthenticated_input": {"type": ["boolean", "null"]},
            "agent_id": {"type": ["string", "null"]},
            "is_approval": {"type": ["boolean", "null"], "description": "True for approval steps, false for manual input."},
            "workflow": {"type": ["string", "integer", "null"], "description": "IRI or pk of the paused workflow."},
        },
    },
    "ManualInputResume": {
        "type": "object",
        "description": "Response from resuming a manual-input step.",
        "properties": {
            "task_id": {"type": ["string", "null"]},
            "message": {"type": ["string", "null"]},
        },
    },
    "Notification": {
        "type": "object",
        "description": "A per-user system (bell-icon) notification (`/api/rule/api/system-notification/notifications/`).",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "content": {"type": ["string", "null"], "description": "Notification body text."},
            "entity_type": {"type": ["string", "null"]},
            "event_type": {"type": ["string", "null"]},
            "entity_id": {"type": ["string", "null"]},
            "read": {"type": ["boolean", "null"]},
            "dismissible": {"type": ["boolean", "null"]},
            "created_on": {"type": ["string", "null"]},
            "user": {"type": ["string", "null"], "description": "User IRI."},
        },
    },
    "NotificationPurge": {
        "type": "object",
        "description": "Response from purging notifications.",
        "properties": {
            "result": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
        },
    },
    "CrontabScheduleModel": {
        "type": "object",
        "description": "Crontab fields for a scheduled task.",
        "properties": {
            "minute": {"type": ["string", "null"], "example": "0"},
            "hour": {"type": ["string", "null"], "example": "9"},
            "day_of_month": {"type": ["string", "null"], "example": "*"},
            "month_of_year": {"type": ["string", "null"], "example": "*"},
            "day_of_week": {"type": ["string", "null"], "example": "1-5"},
            "timezone": {"type": ["string", "null"], "example": "UTC"},
        },
    },
    "ScheduledTask": {
        "type": "object",
        "description": "A periodic task under `/api/wf/api/scheduled/` - a nested crontab + a `kwargs.wf_iri` pointing at the workflow.",
        "properties": {
            "id": {"type": ["string", "null"], "description": "Per-request Fernet token - resolve by `name`."},
            "name": {"type": ["string", "null"]},
            "crontab": {"$ref": "#/components/schemas/CrontabScheduleModel"},
            "task": {"type": ["string", "null"], "description": "Celery task path."},
            "kwargs": {"type": "object", "description": "Carries `wf_iri` (the workflow IRI to run)."},
            "enabled": {"type": ["boolean", "null"]},
            "one_off": {"type": ["boolean", "null"]},
            "last_run_at": {"type": ["string", "null"]},
            "total_run_count": {"type": ["integer", "null"]},
            "description": {"type": ["string", "null"]},
        },
    },
    "TriggerResponse": {
        "type": "object",
        "description": "Response from triggering a playbook - carries the `task_id` to poll.",
        "properties": {
            "task_id": {"type": ["string", "array", "null"],
                        "description": "The run's task id (or ids for fan-out). May be absent on a misconfigured trigger."},
        },
    },
    "ConnectorConfigSummary": {
        "type": "object",
        "description": "A lightweight connector-config reference (one entry per config on an installed connector).",
        "properties": {
            "id": {"type": ["integer", "null"]},
            "config_id": {"type": ["string", "null"], "description": "UUID of the config."},
            "name": {"type": ["string", "null"]},
            "default": {"type": "boolean"},
        },
    },
    "InstalledConnector": {
        "type": "object",
        "description": "An installed connector listing from `/api/integration/connectors/`.",
        "properties": {
            "id": {"type": ["integer", "null"], "description": "Integer connector id (used in config + execute bodies)."},
            "name": {"type": ["string", "null"]},
            "version": {"type": ["string", "null"]},
            "label": {"type": ["string", "null"]},
            "active": {"type": ["boolean", "null"]},
            "system": {"type": ["boolean", "null"]},
            "config_count": {"type": ["integer", "null"]},
            "status": {"type": ["string", "null"]},
            "configurations": {"type": "array", "items": {"$ref": "#/components/schemas/ConnectorConfigSummary"}},
            "ingestion_supported": {"type": ["boolean", "null"]},
            "agent": {"type": ["string", "null"], "description": "Agent id if installed on a remote agent."},
            "development": {"type": ["boolean", "null"]},
            "created": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
        },
    },
    "ConnectorConfig": {
        "type": "object",
        "description": "A connector configuration record (from `/api/integration/configuration/`).",
        "properties": {
            "id": {"type": ["integer", "null"]},
            "config_id": {"type": ["string", "null"], "description": "UUID - the `config` value passed to execute."},
            "name": {"type": ["string", "null"]},
            "default": {"type": "boolean"},
            "status": {"type": ["integer", "null"]},
            "config": {"type": "object", "description": "The connector's field values."},
            "connector": {"type": ["integer", "null"], "description": "Integer connector id."},
            "agent": {"type": ["string", "null"], "description": "Agent id for remote-agent configs."},
        },
    },
    "ExecuteResult": {
        "type": "object",
        "description": "Result of `POST /api/integration/execute/`.",
        "properties": {
            "operation": {"type": ["string", "null"], "description": "The connector action that ran."},
            "status": {"type": ["string", "null"], "description": "Success / failure."},
            "message": {"type": ["string", "null"]},
            "data": {"type": "object", "description": "Action output payload."},
        },
    },
    "HealthcheckResult": {
        "type": "object",
        "description": "Result of a connector health check.",
        "properties": {
            "status": {"type": ["string", "null"]},
            "message": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"], "description": "Connector name."},
            "version": {"type": ["string", "null"]},
            "config_id": {"type": ["string", "null"]},
            "request_id": {"type": ["string", "null"]},
            "http_status": {"type": ["integer", "null"]},
            "ok": {"type": ["boolean", "null"], "description": "True if the config is healthy."},
        },
    },
    "ModulePermission": {
        "type": "object",
        "description": "Per-module CRUD+execute grant on a role.",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "canCreate": {"type": ["boolean", "null"]},
            "canRead": {"type": ["boolean", "null"]},
            "canUpdate": {"type": ["boolean", "null"]},
            "canDelete": {"type": ["boolean", "null"]},
            "canExecute": {"type": ["boolean", "null"]},
            "module": {"type": ["string", "null"], "description": "Module type the grant covers."},
        },
    },
    "Role": {
        "type": "object",
        "description": "An RBAC role (`/api/3/roles`).",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Role"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "modulePermissions": {"type": "array", "items": {"$ref": "#/components/schemas/ModulePermission"}},
        },
    },
    "Team": {
        "type": "object",
        "description": "A team / ownership group (`/api/3/teams`).",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Team"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "actors": {"type": "array", "items": {"type": ["string", "object"]},
                       "description": "Member IRIs (users / appliances / API keys)."},
        },
    },
    "WidgetRecord": {
        "type": "object",
        "description": "A widget record (`/api/3/widgets`): the pyfsr model `client.widgets` upload/publish/list/get return. Unmodeled layout keys (`tree`, ...) ride along as extra properties.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"], "description": "Alphanumeric widget slug."},
            "version": {"type": ["string", "null"]},
            "title": {"type": ["string", "null"]},
            "subTitle": {"type": ["string", "null"]},
            "draft": {"type": ["boolean", "null"], "description": "True while the widget is still in development (unpublished)."},
            "installed": {"type": ["boolean", "null"]},
            "enablePublish": {"type": ["boolean", "null"]},
            "metadata": {"type": ["object", "null"]},
        },
    },
    # AI traces (client.ai.traces) -- hand-shaped from pyfsr's live-verified
    # TraceSummary/TraceSpan/TraceNode/ExecutionTree models.
    "TraceSummary": {
        "type": "object",
        "description": "One row of `GET /api/ai/traces/` -- a top-level agent run.",
        "required": ["trace_id"],
        "properties": {
            "trace_id": {"type": "string"},
            "parent_trace_id": {"type": ["string", "null"],
                                "description": "Set when this run was submitted by another run (investigations fan out into child traces)."},
            "root_span_id": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"], "description": "Agent or pipeline that produced the run."},
            "status": {"type": ["string", "null"], "description": "e.g. `RUNNING`, `COMPLETED`, `FAILED`."},
            "session_id": {"type": ["string", "null"], "description": "Chat session the run belongs to (aiAssistant widget runs)."},
            "user_id": {"type": ["string", "null"]},
            "start_time": {"type": ["string", "null"], "description": "ISO-8601."},
            "end_time": {"type": ["string", "null"], "description": "ISO-8601; null while the run is still going."},
            "total_tokens": {"type": ["integer", "null"], "description": "LLM tokens consumed by the whole run."},
            "total_cost": {"type": ["number", "null"], "description": "Estimated cost in USD."},
            "span_counts": {"type": ["object", "null"],
                            "description": "Span count per type, e.g. `{\"LLM\": 2, \"TOOL\": 1}`."},
            "tags": {"type": "array", "items": {}},
        },
    },
    "TraceSpan": {
        "type": "object",
        "description": "One span of a trace (`GET /api/ai/traces/spans/{span_id}` or a row of `.../{trace_id}/spans`). For an `LLM` span the prompt is under `input.payload.params.messages` and the reply under `output` (`content`, `tools`, `usage`, `provider`, `model`); for a `TOOL` span `output` is the tool result.",
        "required": ["span_id"],
        "properties": {
            "span_id": {"type": "string"},
            "trace_id": {"type": ["string", "null"]},
            "parent_span_id": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"], "description": "Step name (tool name for `TOOL` spans, agent name for `AGENT` spans)."},
            "span_type": {"type": ["string", "null"],
                          "description": "`AGENT` / `LLM` / `LLM_WRAPPER` / `TOOL` / `SKILL_RETRIEVER` / `DOCUMENT_SEARCH` / `CUSTOM`."},
            "status": {"type": ["string", "null"]},
            "start_time": {"type": ["string", "null"]},
            "end_time": {"type": ["string", "null"]},
            "duration_ms": {"type": ["number", "null"]},
            "input": {"description": "Raw span input. For `TOOL` spans carries the `tool_call` (`name`, `args`)."},
            "output": {"description": "Raw span output. For `LLM` spans: `content`, `tools`, `usage`, `provider`, `model`. For `TOOL` spans: the tool result."},
            "error": {"description": "Failure detail when `status` is failed."},
            "attributes": {"type": ["object", "null"]},
            "session_id": {"type": ["string", "null"]},
            "user_id": {"type": ["string", "null"]},
        },
    },
    "TraceNode": {
        "type": "object",
        "description": "A node of a trace tree (`GET /api/ai/traces/{trace_id}`, `.../execution-tree`, `.../spans/{span_id}/tree`). Carries a span summary (no full I/O -- fetch the span for that) plus its `children`.",
        "required": ["span_id"],
        "properties": {
            "span_id": {"type": "string"},
            "name": {"type": ["string", "null"]},
            "span_type": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "start_time": {"type": ["string", "null"]},
            "end_time": {"type": ["string", "null"]},
            "start_offset_ms": {"type": ["number", "null"], "description": "Offset from the tree root."},
            "duration_ms": {"type": ["number", "null"]},
            "attributes": {"type": ["object", "null"]},
            "child_count": {"type": ["integer", "null"]},
            "children": {"type": "array", "items": {"$ref": "#/components/schemas/TraceNode"}},
            "children_truncated": {"type": ["boolean", "null"],
                                   "description": "True when the subtree was cut off (fetch the child's own tree for more)."},
            "io_preview": {"description": "Trimmed input/output preview when requested."},
        },
    },
    "ExecutionTree": {
        "type": "object",
        "description": "A run plus every run it submitted (`GET /api/ai/traces/{trace_id}/execution-tree`) -- what the Trace Flow panel renders. An investigation typically spans ~10 traces, stitched into one `root` tree.",
        "properties": {
            "root_trace_id": {"type": ["string", "null"]},
            "traces": {"type": "array", "items": {"type": ["string", "object"]},
                       "description": "The stitched trace ids (or summaries)."},
            "root": {"$ref": "#/components/schemas/TraceNode"},
        },
    },
    # TAXII (client.taxii) -- hand-shaped from pyfsr's live-verified models.
    "TaxiiDiscovery": {
        "type": "object",
        "description": "TAXII server descriptor (`GET /api/taxii/1/`) -- the endpoint clients call first to confirm protocol compatibility.",
        "properties": {
            "title": {"type": ["string", "null"], "description": "Server title (e.g. `FortiSOAR TAXII Server`)."},
            "description": {"type": ["string", "null"]},
            "default": {"type": ["string", "null"], "description": "Default collections URL (`/api/taxii/1/collections/`)."},
            "versions": {"type": "array", "items": {"type": "string"},
                         "description": "Supported TAXII media types, e.g. `application/taxii+json;version=2.1`."},
            "max_content_length": {"type": ["integer", "null"], "description": "Max request body size the server accepts (bytes)."},
        },
    },
    "TaxiiCollection": {
        "type": "object",
        "description": "One TAXII collection. On FortiSOAR a collection *is* a system query: `id` maps to a system-query uuid, so a dataset is addressable as a TAXII collection.",
        "properties": {
            "id": {"type": ["string", "null"], "description": "Collection id (a system-query uuid)."},
            "title": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "can_read": {"type": ["boolean", "null"], "description": "Caller may read objects from this collection."},
            "can_write": {"type": ["boolean", "null"], "description": "Caller may add objects (typically false -- publishing goes through system queries)."},
            "media_types": {"type": "array", "items": {"type": "string"},
                            "description": "e.g. `application/stix+json;version=2.1`."},
        },
    },
    "TaxiiManifestEntry": {
        "type": "object",
        "description": "One row of a TAXII manifest: object metadata without the object body.",
        "properties": {
            "id": {"type": ["string", "null"], "description": "STIX object id."},
            "date_added": {"type": ["string", "null"], "description": "When the object entered the collection."},
            "version": {"type": ["string", "null"], "description": "STIX object version."},
            "media_type": {"type": ["string", "null"]},
        },
    },
    "TaxiiManifest": {
        "type": "object",
        "description": "Manifest envelope (`GET /api/taxii/1/collections/{uuid}/manifest`).",
        "properties": {
            "more": {"type": ["boolean", "null"], "description": "True when another page follows."},
            "next": {"type": ["string", "null"], "description": "Cursor for the next page."},
            "objects": {"type": "array", "items": {"$ref": "#/components/schemas/TaxiiManifestEntry"}},
            "totalItems": {"type": ["integer", "null"]},
        },
    },
    "TaxiiObjectsEnvelope": {
        "type": "object",
        "description": "STIX objects envelope (`GET /api/taxii/1/collections/{uuid}/objects[/{stixId}]`). FortiSOAR's non-standard wrapper (no TAXII 2.1 `more`/`next` semantics beyond the listed keys); paginate with `limit` + `added_after`.",
        "properties": {
            "more": {"type": ["boolean", "null"]},
            "next": {"type": ["string", "null"]},
            "objects": {"type": "array",
                        "items": {"type": "object", "additionalProperties": True,
                                  "description": "One STIX object (`type`, `id`, `spec_version`, `created`, `modified`, ...)."}},
            "totalItems": {"type": ["integer", "null"]},
        },
    },
    # Connector internals (client.connectors) -- hand-shaped from pyfsr's
    # live-verified models plus 8.0.0 captures.
    "ConnectorDefinition": {
        "type": "object",
        "additionalProperties": True,
        "description": "A connector's definition (`POST /api/integration/connectors/{connector}/{version}/`): metadata, operations, config schema and default configuration. `client.connectors.definition()` parses this.",
        "properties": {
            "name": {"type": ["string", "null"]},
            "version": {"type": ["string", "null"]},
            "label": {"type": ["string", "null"], "description": "Display name."},
            "description": {"type": ["string", "null"]},
            "publisher": {"type": ["string", "null"]},
            "category": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
            "active": {"type": ["boolean", "null"]},
            "operations": {"type": "array", "items": {"type": "object", "additionalProperties": True},
                           "description": "The connector's operations (name, editable, sample, parameters, ...)."},
            "config_schema": {"type": ["object", "null"],
                              "description": "Configuration fields the connector requires (`client.connectors.config_schema()` reads this)."},
            "configuration": {"description": "Default configuration values."},
        },
    },
    "DependencyStatus": {
        "type": "object",
        "description": "Connector dependency check (`GET`/`POST /api/integration/connectors/dependencies_check/{connector}/{version}/`).",
        "properties": {
            "dependencies_installed": {"type": ["boolean", "null"]},
            "message": {"type": ["string", "null"], "description": "What is missing or in progress (POST returns e.g. a `retrying` status)."},
        },
    },
    "IngestionMetadata": {
        "type": "object",
        "additionalProperties": True,
        "description": "One data-ingestion configuration (`POST /api/integration/data-import/`, rows of `GET .../data-import/`): binds a connector configuration to playbooks + a data mapping.",
        "properties": {
            "id": {"type": ["integer", "null"]},
            "name": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "configuration": {"type": ["string", "null"], "description": "Connector configuration id this ingestion binds to."},
            "connector": {"type": ["object", "null"], "description": "Connector reference (id, name, version)."},
            "data_mapping": {"type": ["object", "null"]},
            "playbooks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            "metadata": {"type": ["object", "null"]},
            "sample_data": {"description": "Sample record captured for the mapping."},
            "owners": {"type": "array", "items": {}},
            "status": {"type": ["string", "null"]},
            "created_by": {"type": ["string", "null"]},
            "modified_by": {"type": ["string", "null"]},
        },
    },
    "IngestionPage": {
        "type": "object",
        "description": "Page envelope of `GET /api/integration/data-import/` (FortiSOAR's own paging shape, not hydra).",
        "properties": {
            "data": {"type": "array", "items": {"$ref": "#/components/schemas/IngestionMetadata"}},
            "status": {"type": ["string", "null"]},
            "totalItems": {"type": ["integer", "null"]},
            "itemsPerPage": {"type": ["integer", "null"]},
            "nextPage": {"type": ["integer", "boolean", "null"]},
            "previousPage": {"type": ["integer", "boolean", "null"]},
        },
    },
    "AgentConnectorStatus": {
        "type": "object",
        "description": "Per-agent connector push result (`POST /api/integration/connectors/agents/{name}/{version}/`) -- one row per agent the connector was pushed to.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": ["string", "null"]},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "agent": {"type": ["string", "null"], "description": "Agent IRI the connector was pushed to."},
            "agentId": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"], "description": "Connector name."},
            "version": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "label": {"type": ["string", "null"]},
            "errorMessage": {"type": ["string", "null"]},
            "progressPercent": {"type": ["integer", "null"]},
        },
    },
    # Picklists (client.picklists) -- the taxonomy records.
    "PicklistItem": {
        "type": "object",
        "description": "One option of a picklist (`GET`/`POST /api/3/picklists`). Its `@id` is the IRI records store on picklist fields; `listName` points back at the owning picklist.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Picklist"},
            "id": {"type": ["integer", "null"]},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "itemValue": {"type": ["string", "null"], "description": "The friendly option value."},
            "listName": {"oneOf": [{"type": "string"}, {"type": "object"}],
                         "description": "IRI (or expanded record) of the owning picklist name."},
            "orderIndex": {"type": ["integer", "null"], "description": "Sort key within the picklist."},
            "color": {"type": ["string", "null"]},
            "icon": {"type": ["string", "null"]},
            "importedBy": {"type": "array", "items": {}},
        },
    },
    "PicklistName": {
        "type": "object",
        "description": "A picklist list -- the taxonomy an option belongs to (`GET`/`POST /api/3/picklist_names`). `name` is unique instance-wide (a duplicate POST 409s).",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "PicklistName"},
            "id": {"type": ["integer", "null"]},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"], "description": "Picklist name, unique instance-wide."},
            "system": {"type": ["boolean", "null"], "description": "True for the shipped system picklists."},
            "picklists": {"type": ["array", "null"], "items": {"$ref": "#/components/schemas/PicklistItem"},
                          "description": "Embedded options (present only when the request asks for `$relationships=true`)."},
            "importedBy": {"type": "array", "items": {}},
        },
    },
    # MCP server configuration records (`/api/3/mcp_configurations`).
    "MCPServerConfig": {
        "type": "object",
        "additionalProperties": True,
        "description": "A registered MCP server (`/api/3/mcp_configurations`). `authentication` is stored as a JSON *string* (write-only semantics: the appliance never echoes secrets).",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "mcp_configurations"},
            "id": {"type": ["integer", "null"]},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "url": {"type": ["string", "null"], "description": "MCP endpoint URL (http/sse transport) -- e.g. `https://<host>/mcp/modules/`."},
            "transport": {"type": ["string", "null"], "description": "`http` or `sse`."},
            "type": {"type": ["string", "null"], "description": "`FSR` for built-in gateways; `Custom` for external servers."},
            "active": {"type": ["boolean", "null"]},
            "timeout": {"type": ["integer", "null"]},
            "command": {"type": ["string", "null"], "description": "Stdio transport command (local servers)."},
            "authentication": {"type": ["string", "null"],
                               "description": "Stored auth block as a JSON string (e.g. `{\"type\": \"FSR\"}`); never echoes secrets."},
            "description": {"type": ["string", "null"]},
            "metadata": {"type": ["object", "null"]},
            "recordTags": {"type": "array", "items": {}},
        },
    },
    # Module metadata (staging drafts and published records share the shape).
    "ModelMetadata": {
        "type": "object",
        "additionalProperties": True,
        "description": "A module's metadata record (`/api/3/model_metadatas`, `/api/3/staging_model_metadatas`): table flags, display name, descriptions, and the `attributes` list that drives `src/module_to_schema.py`.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "ModelMetadata"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "type": {"type": ["string", "null"], "description": "Module type name (e.g. `alerts`)."},
            "module": {"type": ["string", "null"], "description": "Display module name."},
            "tableName": {"type": ["string", "null"]},
            "parentType": {"type": ["string", "null"], "description": "Parent module for child tables."},
            "displayName": {"type": ["string", "null"]},
            "descriptions": {"type": ["object", "null"], "description": "Per-locale descriptions."},
            "ownable": {"type": ["boolean", "null"]},
            "userOwnable": {"type": ["boolean", "null"]},
            "queueable": {"type": ["boolean", "null"]},
            "trackable": {"type": ["boolean", "null"]},
            "taggable": {"type": ["boolean", "null"]},
            "peerReplicable": {"type": ["boolean", "null"]},
            "indexable": {"type": ["boolean", "null"]},
            "writable": {"type": ["boolean", "null"]},
            "system": {"type": ["boolean", "null"]},
            "softDeleteable": {"type": ["boolean", "null"]},
            "archivable": {"type": ["boolean", "null"]},
            "paused": {"type": ["boolean", "null"]},
            "enableReplication": {"type": ["boolean", "null"]},
            "partitionBy": {"type": ["string", "null"]},
            "archivalCriteria": {"type": ["object", "null"]},
            "archivalFilters": {"type": "array", "items": {}},
            "replicationFilters": {"type": "array", "items": {}},
            "defaultSort": {"type": "array", "items": {"type": "object"}},
            "uniqueConstraint": {"type": "array", "items": {"type": "object"}},
            "attributes": {"type": "array", "items": {"type": "object", "additionalProperties": True},
                           "description": "Field definitions (name, type, required, picklist ref, ...)."},
            "importedBy": {"type": "array", "items": {}},
        },
    },
    # Import / export jobs (Hydra module records).
    "ExportJob": {
        "type": "object",
        "additionalProperties": True,
        "description": "An export job (`POST /api/3/export_jobs`): polls via the job record's `status`/`progressPercent`; the finished artifact lands on `file`.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "ExportJob"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "type": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"], "description": "e.g. `Queued`, `In Progress`, `Exported`."},
            "progressPercent": {"type": ["integer", "null"]},
            "currentlyExporting": {"type": ["object", "null"], "description": "What the job is exporting right now."},
            "errorMessage": {"type": ["string", "null"]},
            "file": {"oneOf": [{"type": "string"}, {"type": "object", "nullable": True}],
                     "description": "File record IRI (or expanded record) of the exported archive."},
            "fileName": {"type": ["string", "null"]},
            "template": {"oneOf": [{"type": "string"}, {"type": "object", "nullable": True}],
                         "description": "Export template the job was created from."},
            "solutionPack": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
        },
    },
    "ImportJob": {
        "type": "object",
        "additionalProperties": True,
        "description": "An import job (`POST /api/3/import_jobs`): `options` carries the wizard's include/merge choices once populated; `logMessages` accumulates per-item import notes.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "ImportJob"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "type": {"type": ["string", "null"], "description": "e.g. `Import Wizard`."},
            "status": {"oneOf": [{"type": "string"}, {"type": "object"}],
                       "description": "Job status; a `result` key carries progress notes (`Import job options populated`)."},
            "progressPercent": {"type": ["integer", "null"]},
            "currentlyImporting": {"type": ["object", "null"]},
            "errorMessage": {"type": ["string", "null"]},
            "file": {"oneOf": [{"type": "string"}, {"type": "object", "nullable": True}],
                     "description": "The uploaded package's file record."},
            "options": {"type": ["object", "null"],
                        "description": "Wizard options: per-item `include` + `mergeType` for playbooks, modules, etc."},
            "logMessages": {"type": "array", "items": {}},
            "solutionPack": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
        },
    },
    "ImportJobStatus": {
        "type": "object",
        "description": "Lightweight import-job status (`GET /api/import/{job_uuid}`): the job's `@type` plus a `status.result` note (e.g. `Import job options populated`). The full job record lives on `/api/3/import_jobs`.",
        "properties": {
            "@type": {"type": "string", "example": "ImportJob"},
            "status": {"type": "object",
                       "properties": {"result": {"type": "string"}},
                       "description": "Progress note."},
        },
    },
    # System / licensing (8.0.0 captures).
    "LicenseInfo": {
        "type": "object",
        "additionalProperties": True,
        "description": "License state (`GET /api/auth/license`). Multi-node fields (`*_nodes`) matter on HA setups; `POST /api/auth/license` (installing a license) is a privileged operation this spec documents but never exercises.",
        "properties": {
            "details": {"type": ["string", "null"], "description": "License details blob (serial, node id, product, version)."},
            "edition": {"type": ["string", "null"], "description": "e.g. `Enterprise`."},
            "type": {"type": ["string", "null"]},
            "sub_type": {"type": ["string", "null"]},
            "setup_type": {"type": ["string", "null"]},
            "product_name": {"type": ["string", "null"]},
            "expired": {"type": ["boolean", "null"]},
            "expiring_on": {"type": ["integer", "null"], "description": "Epoch seconds the license expires."},
            "remaining_days": {"type": ["integer", "null"]},
            "duplicate": {"type": ["boolean", "null"], "description": "True when another appliance runs the same license (FortiFlex conflict)."},
            "device_uuid_changed": {"type": ["boolean", "null"]},
            "is_cloud_instance": {"type": ["boolean", "null"]},
            "nodes": {"type": "array", "items": {"type": "object"}},
            "users": {"type": ["integer", "null"], "description": "Licensed user count."},
            "user_stats": {"type": ["object", "null"]},
        },
    },
    "ClusterNodeHealth": {
        "type": "object",
        "additionalProperties": True,
        "description": "One node's health row (`GET /api/auth/cluster/health` answers one per cluster node).",
        "properties": {
            "node_id": {"type": ["string", "null"]},
            "node_name": {"type": ["string", "null"]},
            "mode": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"], "description": "Overall node status."},
            "connectivity": {"type": ["object", "null"]},
            "cpu": {"type": ["object", "null"]},
            "disk": {"type": ["object", "null"]},
            "memory": {"type": ["object", "null"]},
            "services": {"type": ["object", "null"], "description": "Per-service states."},
            "workflow": {"type": ["object", "null"]},
            "replication_stat": {"type": ["object", "null"]},
            "misc_stat": {"type": ["object", "null"]},
            "timestamp": {"type": ["integer", "null"]},
            "health_details_collect_time": {"type": ["integer", "null"]},
        },
    },
    "PublicLicenseResponse": {
        "type": "object",
        "description": "License deployment result (`POST /api/public/license`).",
        "properties": {
            "depl_status": {"type": ["string", "null"], "description": "Deployment status indicator."},
            "depl_message": {"type": ["string", "null"], "description": "Human-readable outcome."},
        },
    },
    "VersionInfo": {
        "type": "object",
        "description": "Appliance version (`GET /api/version`).",
        "properties": {
            "version": {"type": "string", "description": "e.g. `8.0.0-6034`."},
        },
    },
    "FeatureAccess": {
        "type": "object",
        "description": "Entitlement gates (`GET /api/product/feature-access`).",
        "properties": {
            "productType": {"type": ["string", "null"]},
            "restricted_feature": {"type": "array", "items": {"type": "string"},
                                   "description": "Features the license tier does not unlock."},
            "restricted_url_states": {"type": "array", "items": {"type": "string"}},
        },
    },
    "DailyActionCount": {
        "type": "object",
        "description": "Workflow action budget (`GET /api/wf/workflow/config/`) -- the playbooks/day quota and what's left of it.",
        "properties": {
            "daily_action_limit": {"type": ["integer", "null"]},
            "remaining_actions": {"type": ["integer", "null"]},
            "reset_time": {"type": ["integer", "null"], "description": "Epoch seconds the quota resets."},
            "last_update_time": {"type": ["number", "null"]},
        },
    },
    "PermissionMap": {
        "type": "object",
        "additionalProperties": True,
        "description": "The caller's effective permissions (`GET /api/permissions/current`): one entry per module/resource (e.g. `alerts`, `agents`, `ai_agents`) with its allowed operations.",
        "properties": {
            "alerts": {"type": ["object", "null"], "description": "Example entry; every module key follows the same shape."},
        },
    },
    "CurrentUser": {
        "type": "object",
        "additionalProperties": True,
        "description": "The authenticated principal (`GET /api/3/actors/current`): a Person-shaped record carrying the caller's `@permissions` block and `@settings` IRI.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Person"},
            "@permissions": {"type": "object",
                             "description": "Effective permission flags for the caller."},
            "@settings": {"$ref": "#/components/schemas/IRI"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "userId": {"type": ["string", "null"], "description": "Login id."},
            "type": {"type": ["string", "null"], "description": "Account type (Person / ApiKey ...)."},
            "userType": {"type": ["integer", "null"]},
            "accessType": {"type": ["string", "null"]},
            "firstname": {"type": ["string", "null"]},
            "lastname": {"type": ["string", "null"]},
            "email": {"type": ["string", "null"]},
            "companyId": {"oneOf": [{"type": "string"}, {"type": "object"}]},
            "avatar": {"type": ["string", "null"]},
            "title": {"type": ["string", "null"]},
            "department": {"type": ["string", "null"]},
        },
    },
    # Audit (the gateway's own paging envelope, not hydra).
    "AuditActivity": {
        "type": "object",
        "additionalProperties": True,
        "description": "One audited activity row (`POST /api/gateway/audit/activities`): what changed, on which entity, by whom.",
        "properties": {
            "id": {"description": "Audit row id."},
            "component": {"type": ["string", "null"], "description": "Owning service, e.g. `crudhub`."},
            "subComponent": {"type": ["string", "null"]},
            "operation": {"type": ["string", "null"], "description": "e.g. `Create`, `Update`, `Delete`."},
            "entityType": {"type": ["string", "null"]},
            "entitySingularName": {"type": ["string", "null"]},
            "entityUuid": {"type": ["string", "null"]},
            "title": {"type": ["string", "null"]},
            "displayName": {"type": ["string", "null"]},
            "user": {"type": ["string", "null"], "description": "Who performed the action."},
            "userId": {"type": ["integer", "null"]},
            "transactionDate": {"type": ["integer", "null"], "description": "Epoch millis."},
            "source": {"type": ["string", "null"]},
            "data": {"description": "Change payload (before/after, or created entity)."},
            "teamIris": {"type": "array", "items": {"type": "string"}},
            "userOwnerIris": {"type": "array", "items": {"type": "string"}},
        },
    },
    "AuditActivityPage": {
        "type": "object",
        "description": "Spring-style page of audit rows (`POST /api/gateway/audit/activities`) -- not hydra.",
        "properties": {
            "content": {"type": "array", "items": {"$ref": "#/components/schemas/AuditActivity"}},
            "first": {"type": ["boolean", "null"]},
            "number": {"type": ["integer", "null"], "description": "Zero-based page number."},
        },
    },
    "AuditCount": {
        "type": "object",
        "description": "Row count for an audit filter (`POST /api/gateway/audit/activities/count`).",
        "properties": {
            "total": {"type": "integer"},
        },
    },
    # Metadata / misc records.
    "LlmActivityLog": {
        "type": "object",
        "additionalProperties": True,
        "description": "One LLM call record (`/api/3/llm_activity_logs`): token counts, latency and cost per AI interaction.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "llm_activity_logs"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "correlationID": {"type": ["string", "null"], "description": "Ties the call to its trace/session."},
            "title": {"type": ["string", "null"]},
            "modelName": {"type": ["string", "null"]},
            "provider": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "error": {"description": "Failure detail when status is failed."},
            "prompt": {"description": "Prompt sent to the model."},
            "response": {"description": "Model reply."},
            "inputTokens": {"type": ["integer", "null"]},
            "outputTokens": {"type": ["integer", "null"]},
            "totalTokens": {"type": ["integer", "null"]},
            "latencyMs": {"type": ["integer", "null"]},
            "costUSD": {"type": ["number", "null"]},
        },
    },
    "AuthConfigRow": {
        "type": "object",
        "description": "One authentication setting row (`GET /api/auth/config`).",
        "properties": {
            "id": {"type": ["integer", "null"]},
            "section": {"type": ["string", "null"]},
            "key": {"type": ["string", "null"]},
            "dataType": {"type": ["string", "null"]},
            "value": {"description": "Setting value (type per `dataType`)."},
        },
    },
    "AuthConfigWriteResult": {
        "type": "object",
        "description": "Result of `PUT /api/auth/config`.",
        "properties": {
            "response": {"type": "string", "example": "Success"},
        },
    },
    "DynamicVariable": {
        "type": "object",
        "description": "A playbook dynamic variable (`/api/wf/api/dynamic-variable/`) -- global `$(variables)` available inside playbooks.",
        "properties": {
            "id": {"description": "Variable id."},
            "name": {"type": ["string", "null"]},
            "value": {"description": "Current value."},
            "default_value": {"description": "Fallback when unset."},
        },
    },
    "ViewConfig": {
        "type": "object",
        "additionalProperties": True,
        "description": "A module view definition (`/api/views/1/{name}`): grid/list configuration for one module's UI.",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"], "description": "View name (e.g. `Default`)."},
            "module": {"type": ["string", "null"]},
            "type": {"type": ["string", "null"]},
            "isDefault": {"type": ["boolean", "null"]},
            "system": {"type": ["boolean", "null"]},
            "config": {"type": ["object", "null"], "description": "Columns, filters layout, page size."},
            "filters": {"type": ["object", "null"]},
            "viewOptions": {"type": ["object", "null"]},
            "owner": {"oneOf": [{"type": "string"}, {"type": "object"}]},
            "importedBy": {"type": "array", "items": {}},
        },
    },
    "ExportTemplate": {
        "type": "object",
        "additionalProperties": True,
        "description": "An export template (`/api/3/export_templates`): the named, reusable selection of content an export job packages.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "ExportTemplate"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "type": {"type": ["string", "null"]},
            "options": {"type": ["object", "null"], "description": "What the template includes (playbooks, modules, ...)."},
            "lastExportDate": {"type": ["integer", "null"]},
            "exportJobs": {"type": "array", "items": {"type": ["string", "object"]}},
            "solutionPack": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
        },
    },
    "ExportTriggerResult": {
        "type": "object",
        "description": "Result of `PUT /api/export` (query-param body): the created export job's reference.",
        "properties": {
            "@type": {"type": "string", "example": "ExportJob"},
            "jobUuid": {"$ref": "#/components/schemas/UUID"},
        },
    },
    "PublishStatus": {
        "type": "object",
        "description": "Schema-publish workflow state (`PUT /api/publish/revert`, `GET /api/publish/error`).",
        "properties": {
            "@type": {"type": "string"},
            "status": {"description": "Publish/revert outcome."},
            "last_publish_time": {"type": ["integer", "null"], "description": "Epoch of the last successful publish."},
        },
    },
    # Playbook runs (8.0.0 captures; the run record and its step rows).
    "WorkflowRun": {
        "type": "object",
        "additionalProperties": True,
        "description": "One playbook run (`GET /api/wf/api/workflows/{pk}/`, rows of `historical-workflows` and the workflow-logs queries). `steps` carries the per-step rows (same shape as `GET /api/wf/api/historical-steps/`).",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "workflow"},
            "name": {"type": ["string", "null"], "description": "Playbook name that ran."},
            "status": {"type": ["string", "null"], "description": "e.g. `running`, `completed`, `failed`."},
            "result": {"description": "The run's final result payload."},
            "created": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
            "node_name": {"type": ["string", "null"], "description": "Node that executed the run."},
            "debug": {"type": ["boolean", "null"], "description": "True for debug runs (steps keep full I/O)."},
            "env": {"type": ["object", "null"], "description": "Environment variables the run saw."},
            "metadata": {"type": ["object", "null"]},
            "parent_wf": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}],
                          "description": "Parent run when this was spawned by another playbook."},
            "peer_details": {"type": ["object", "null"]},
            "steps": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            "tags": {"type": "array", "items": {}},
            "template_iri": {"type": ["string", "null"], "description": "The playbook template that was executed."},
            "user": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
        },
    },
    "HistoricalStep": {
        "type": "object",
        "additionalProperties": True,
        "description": "One executed step (`GET /api/wf/api/historical-steps/`): the step's inputs, result and timing inside its parent run.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string"},
            "name": {"type": ["string", "null"], "description": "Step name."},
            "status": {"type": ["string", "null"]},
            "task_id": {"type": ["string", "null"], "description": "Run task id this step belongs to."},
            "workflow_id": {"oneOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]},
            "parent_id": {"oneOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]},
            "input": {"description": "Step input data."},
            "result": {"description": "Step output data."},
            "args": {"type": ["object", "null"]},
            "data": {"type": ["object", "null"]},
            "initial": {"type": ["boolean", "null"]},
            "created": {"type": ["string", "null"]},
            "started": {"type": ["string", "null"]},
            "completed": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
        },
    },
    "JinjaRenderResult": {
        "type": "object",
        "description": "Rendered template (`POST /api/wf/api/jinja-editor/`) -- the Jinja editor's preview call.",
        "properties": {
            "result": {"description": "Rendered output."},
        },
    },
    "RunCount": {
        "type": "object",
        "description": "Playbook run count (`GET /api/wf/api/workflows/count/`).",
        "properties": {
            "count": {"type": "integer"},
        },
    },
    "ApprovalResult": {
        "type": "object",
        "description": "Result of `POST /api/wf/api/workflows/{pk}/approval/` (the legacy list route).",
        "properties": {
            "approvals": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        },
    },
    "RetryResult": {
        "type": "object",
        "description": "Result of `GET /api/wf/api/workflows/{pk}/retry/`.",
        "properties": {
            "task_id": {"type": ["string", "null"], "description": "Task id of the retried run."},
            "result": {"description": "Retry outcome payload."},
        },
    },
    # Connector internals (development IDE + gateway).
    "AgentHeartbeat": {
        "type": "object",
        "additionalProperties": True,
        "description": "One agent's heartbeat row (`GET /api/integration/agent-heartbeat/{agent}/`): connector + configuration the agent last reported, with its remote status.",
        "properties": {
            "id": {"description": "Heartbeat row id."},
            "agent": {"oneOf": [{"type": "string"}, {"type": "object"}], "description": "Agent IRI or expanded record."},
            "connector": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "configuration": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "action": {"type": ["string", "null"], "description": "Pending action for the agent, if any."},
            "remote_status": {"type": ["string", "null"]},
            "log_records": {"type": ["integer", "null"], "description": "Log rows the agent has pending/processed."},
            "created": {"type": ["string", "null"]},
            "modified": {"type": ["string", "null"]},
        },
    },
    "ConnectorFileContent": {
        "type": "object",
        "description": "Connector development file fetch (`POST .../development/entity/{id}/files/`).",
        "properties": {
            "fileContent": {"type": "string", "description": "The file's text content."},
        },
    },
    "ConnectorFileTree": {
        "type": "object",
        "description": "Connector development file write (`PUT .../development/entity/{id}/files/`).",
        "properties": {
            "status": {"description": "Write outcome."},
            "tree": {"description": "The connector's file tree after the write."},
        },
    },
    "ConnectorOutputSchema": {
        "type": "object",
        "description": "Output schema probe (`POST /api/integration/connector_output_schema/{connector}/{version}/`).",
        "properties": {
            "status": {"type": ["string", "null"]},
            "data": {"description": "The operation's output schema."},
        },
    },
    "InstallConnectorResult": {
        "type": "object",
        "description": "Result of `POST /api/integration/install-connector/` (connector push to agents).",
        "properties": {
            "message": {"type": ["string", "null"]},
            "remote_status": {"type": ["string", "null"]},
        },
    },
    "MCPServerRef": {
        "type": "object",
        "description": "One entry of `GET /api/ai/mcp` -- the id + name the agent-config UI lists. Resolve to the full record on `/api/3/mcp_configurations`.",
        "properties": {
            "id": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"]},
        },
    },
    "MCPHostedServer": {
        "type": "object",
        "description": "Acknowledgment of `POST /mcp/add/tools` -- the hosted server's coordinates.",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "url": {"type": ["string", "null"], "description": "Gateway URL the server is served under."},
        },
    },
    "MCPServerToolsExport": {
        "type": "object",
        "description": "One server's exported tool catalog (`POST /mcp/config/export` answers a list of these).",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "tools": {"type": "array", "items": {"type": "object", "additionalProperties": True},
                      "description": "Exported tool rows (operation, title, parameters, ...)."},
        },
    },
    "MCPCandidates": {
        "type": "object",
        "description": "Connectors eligible for MCP hosting (`GET /mcp/servers/connector`).",
        "properties": {
            "available": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            "restricted": {"type": "array", "items": {"type": "object", "additionalProperties": True},
                           "description": "Connectors that cannot be hosted (e.g. system connectors)."},
        },
    },
    "UserQuery": {
        "type": "object",
        "additionalProperties": True,
        "description": "A saved query (`POST /api/3/user_queries`) -- the Search page's stored queries.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "UserQuery"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "query": {"type": ["string", "null"], "description": "The stored filter/query string."},
            "advanced": {"type": ["boolean", "null"]},
            "assignee": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "models": {"type": "array", "items": {"type": "string"},
                       "description": "Module types the query spans."},
            "resultCacheSeconds": {"type": ["integer", "null"]},
        },
    },
    "Router": {
        "type": "object",
        "additionalProperties": True,
        "description": "A communication router (`GET /api/3/routers`) -- the mTLS endpoint agents and peers connect through.",
        "properties": {
            "@id": {"$ref": "#/components/schemas/IRI"},
            "@type": {"type": "string", "example": "Router"},
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "name": {"type": ["string", "null"]},
            "address": {"type": ["string", "null"]},
            "type": {"type": ["string", "null"]},
            "tcpPort": {"type": ["integer", "null"]},
            "intraTCPPort": {"type": ["integer", "null"]},
            "apiPort": {"type": ["integer", "null"]},
            "mTLS": {"type": ["boolean", "null"]},
            "sni": {"type": ["string", "null"]},
            "certificate": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "clientCert": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "clientKey": {"oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]},
            "health": {"type": ["string", "null"]},
            "configstatus": {"type": ["string", "null"]},
            "configMessage": {"type": ["string", "null"]},
        },
    },
    # --- Request bodies (live-verified) ---------------------------------------
    # Authenticated as JSON-string on the record; as an object on validate.
    "MCPServerConfigInput": {
        "type": "object",
        "required": ["name", "url", "transport", "type"],
        "description": "Create/update an MCP server registration. `authentication` is a JSON *string* (the appliance stores the block verbatim and never echoes secrets).",
        "properties": {
            "name": {"type": "string"},
            "url": {"type": "string", "description": "MCP endpoint, e.g. `https://<host>/mcp/modules/`."},
            "transport": {"type": "string", "enum": ["http", "sse"]},
            "type": {"type": "string", "description": "`FSR` for built-in gateways; `Custom` for external servers."},
            "authentication": {"type": "string", "description": "Auth block as a JSON string, e.g. `{\"type\": \"FSR\"}` or `{\"type\": \"Bearer\", \"token\": ...}`."},
            "active": {"type": "boolean"},
            "timeout": {"type": "integer"},
            "command": {"type": "string", "description": "Stdio transport command (local servers)."},
            "description": {"type": "string"},
        },
    },
    "RoleCreate": {
        "type": "object",
        "required": ["name"],
        "description": "Create a role. Only `name` is required; attach module grants afterwards via `PUT /api/3/roles/{uuid}` (pyfsr's `grant_module_permissions`).",
        "properties": {
            "name": {"type": "string", "description": "Role name, unique."},
            "description": {"type": "string"},
        },
    },
    "TeamCreate": {
        "type": "object",
        "required": ["name"],
        "description": "Create a team. `parents`/`children`/`siblings` place it in the ownership hierarchy (names, uuids or IRIs): parents see and edit child-owned records, children do not see each other, siblings share records both ways.",
        "properties": {
            "name": {"type": "string", "description": "Team name, unique."},
            "description": {"type": "string"},
            "parents": {"type": "array", "items": {"type": "string"}},
            "children": {"type": "array", "items": {"type": "string"}},
            "siblings": {"type": "array", "items": {"type": "string"}},
        },
    },
    "User": {
        "type": "object",
        "description": "A People record -- the tenant's user directory entry every das login (`/api/auth/users`) hangs off (pyfsr `User`). Captured from a live create -> read -> update -> delete lifecycle. Relationship fields (`roles`, `teams`, `user`, `type`) come back null unless expanded.",
        "properties": {
            "@id": {"type": "string", "description": "IRI, e.g. `/api/3/people/<uuid>`."},
            "@type": {"type": "string"},
            "@context": {"type": "string"},
            "@settings": {"type": "string", "description": "IRI of this user's `/api/3/user_settings` collection."},
            "uuid": {"type": "string"},
            "id": {"type": "integer"},
            "firstname": {"type": "string"},
            "lastname": {"type": "string"},
            "title": {"type": "string"},
            "email": {"type": "string"},
            "department": {"type": "string"},
            "description": {"type": "string"},
            "phoneWork": {"type": "string"},
            "phoneMobile": {"type": "string"},
            "phoneHome": {"type": "string"},
            "phoneFax": {"type": "string"},
            "csActive": {"type": "boolean", "description": "false deactivates the person and frees the license seat."},
            "accessType": {"type": "string", "enum": ["Named", "Concurrent"]},
            "userType": {"type": "string"},
            "type": {"type": "string", "description": "Picklist type IRI; null unless expanded."},
            "avatar": {"description": "Avatar reference; null when unset."},
            "companyId": {"description": "Company reference; null when unset."},
            "sourceControlUsername": {"type": "string", "description": "Username for the source-control (git) integration."},
            "userId": {"type": "string", "description": "UUID of the linked das login in `/api/auth/users`."},
            "createUser": {"description": "Creating user (Person IRI or embedded record)."},
            "modifyUser": {"description": "Last modifying user (Person IRI or embedded record)."},
            "createDate": {"type": "integer", "description": "Epoch seconds."},
            "modifyDate": {"type": "integer", "description": "Epoch seconds."},
            "user": {"type": "object", "description": "Linked das login record (`loginid`, `status`); null unless expanded."},
            "roles": {"type": "array", "items": {"type": "string"}, "description": "Role IRIs; null unless expanded."},
            "teams": {"type": "array", "items": {"type": "string"}, "description": "Team IRIs; null unless expanded."},
        },
    },
    "PersonCreate": {
        "type": "object",
        "required": ["firstname", "lastname", "email", "roles", "user"],
        "description": "Create a People record. The nested `user` block provisions the das login -- omit `status` (or pass 2) and the account is created INACTIVE and cannot log in (das defaults it to status 2). The People POST alone leaves the login passwordless; set the password via `POST /api/3/resetpassword` afterwards (pyfsr's `UsersAPI.create` chains both calls). `teams` is optional on the wire (a teamless user is saved with `teams: []`), but the UI's Add User wizard requires one and team-scoped RBAC may leave a teamless user unable to see or own records -- pyfsr's `UsersAPI.create` warns and lists the tenant's team names when `teams` is omitted.",
        "properties": {
            "firstname": {"type": "string"},
            "lastname": {"type": "string"},
            "email": {"type": "string"},
            "csActive": {"type": "boolean", "description": "pyfsr defaults true."},
            "accessType": {"type": "string", "enum": ["Named", "Concurrent"], "description": "pyfsr defaults `Named`."},
            "roles": {"type": "array", "items": {"type": "string"}, "description": "Role names, UUIDs or IRIs (pyfsr resolves names to UUIDs). At least one required."},
            "teams": {"type": "array", "items": {"type": "string"}, "description": "Team names, UUIDs or IRIs (all three forms live-verified; the assignment sticks either way). Optional on the wire but required by the UI's Add User wizard."},
            "user": {
                "type": "object",
                "required": ["loginid"],
                "properties": {
                    "loginid": {"type": "string"},
                    "password": {"type": "string", "description": "Initial password; must pass the password policy."},
                    "email": {"type": "string"},
                    "status": {"type": "integer", "enum": [1, 2], "description": "1 = active, 2 = inactive. das defaults to 2 when omitted."},
                },
            },
            "department": {"type": "string"},
            "phoneWork": {"type": "string"},
            "phoneMobile": {"type": "string"},
            "description": {"type": "string"},
        },
    },
    "ResetPasswordRequest": {
        "description": "Two accepted shapes. Simple (captured live): `{loginId, password, confirmPassword}`. Full (the UI's Reset Password dialog, pyfsr `reset_password`): `{uuid, currentUUID, loginId, password, sendEmail}` where `uuid` is the People UUID and `currentUUID` the das user UUID. das refuses resetting your own login this way -- use the change-password flow. `sendEmail` defaults to false (pyfsr does not send email).",
        "anyOf": [
            {
                "type": "object",
                "required": ["loginId", "password", "confirmPassword"],
                "properties": {
                    "loginId": {"type": "string"},
                    "password": {"type": "string", "description": "New password; must pass the password policy and history check."},
                    "confirmPassword": {"type": "string"},
                },
            },
            {
                "type": "object",
                "required": ["uuid", "currentUUID", "loginId", "password"],
                "properties": {
                    "uuid": {"type": "string", "description": "People record UUID."},
                    "currentUUID": {"type": "string", "description": "das user UUID from `/api/auth/users`."},
                    "loginId": {"type": "string"},
                    "password": {"type": "string"},
                    "sendEmail": {"type": "boolean", "default": False},
                },
            },
        ],
    },
    "InsightRecord": {
        "type": "object",
        "description": "A saved AI insight on the platform module (`/api/3/insights`) -- a named query bound to a plan execution, rendered by the AI Insight widget (pyfsr `AIInsightsAPI.save`). Captured from a live create -> read -> update -> delete lifecycle.",
        "properties": {
            "@id": {"type": "string", "description": "IRI, e.g. `/api/3/insights/<uuid>`."},
            "@type": {"type": "string"},
            "@context": {"type": "string"},
            "uuid": {"type": "string"},
            "id": {"type": "integer"},
            "title": {"type": "string"},
            "query": {"type": "string", "description": "The investigation question."},
            "socrole": {"type": "string", "description": "Role the insight runs as."},
            "planid": {"type": "string", "description": "UUID of the plan execution backing the insight. Not FK-validated on write (any UUID is accepted)."},
            "active": {"type": "boolean"},
            "conflict": {"type": "boolean"},
            "scheduleid": {"description": "UUID of the schedule the widget creates for the insight; absent/null when run on demand."},
            "recordTags": {"description": "Record tags on the insight."},
            "tenant": {"description": "Tenant reference."},
            "tenantRecordId": {"description": "Tenant record identifier."},
            "createDate": {"type": "integer", "description": "Epoch seconds."},
            "modifyDate": {"type": "integer", "description": "Epoch seconds."},
            "createUser": {"description": "Creating user (Person IRI or embedded record)."},
            "modifyUser": {"description": "Last modifying user (Person IRI or embedded record)."},
        },
    },
    "InsightSaveRequest": {
        "type": "object",
        "required": ["title", "query", "planid"],
        "description": "Save (POST) or update (PUT) a saved insight -- mirrors the AI Insight widget (pyfsr `AIInsightsAPI.save`).",
        "properties": {
            "title": {"type": "string"},
            "query": {"type": "string"},
            "socrole": {"type": "string", "description": "Defaults to `SOC Analyst`."},
            "planid": {"type": "string", "description": "UUID of the plan execution; not FK-validated on write."},
        },
    },
    "AgentAcceptanceRequest": {
        "type": "object",
        "required": ["accepted"],
        "description": "Accept or reject an agent run's result (the human-in-the-loop gate).",
        "properties": {
            "accepted": {"type": "boolean", "description": "`true` approves the run's result; `false` rejects it."},
        },
    },
    "EnrichContextRequest": {
        "type": "object",
        "required": ["query"],
        "description": "Store organizational context for enrichment (the `query` text is indexed for later IOC enrichment lookups).",
        "properties": {
            "query": {"type": "string"},
        },
    },
    "MCPValidateRequest": {
        "type": "object",
        "required": ["url", "transport", "authentication"],
        "description": "Probe an MCP-server config *before* persisting it: FortiSOAR opens the connection and runs `tools/list`. `authentication` is a JSON **object** here (unlike the stored record, where it is a string).",
        "properties": {
            "name": {"type": "string"},
            "url": {"type": "string"},
            "transport": {"type": "string", "enum": ["http", "sse"]},
            "authentication": {"type": "object", "description": "e.g. `{\"type\": \"FSR\"}` (uses the caller's credentials) or `{\"type\": \"Bearer\", \"token\": ...}`."},
            "uuid": {"type": "string", "description": "Set when re-validating an already-registered server."},
        },
    },
    "IngestionMetadataInput": {
        "type": "object",
        "required": ["configuration", "connector"],
        "description": "Create a data-ingestion configuration: binds a connector configuration to ingestion playbooks and a schedule.",
        "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "configuration": {"type": "string", "description": "uuid of the connector configuration to bind."},
            "connector": {"type": "object", "required": ["name"],
                          "properties": {"name": {"type": "string"}, "version": {"type": "string"}},
                          "description": "Connector reference (name + version; empty version = latest)."},
            "metadata": {"type": "object",
                         "properties": {
                             "scheduleId": {"oneOf": [{"type": "string"}, {"type": "null"}]},
                             "scheduleName": {"type": "string"},
                             "scheduleStatus": {"type": "boolean"},
                         },
                         "description": "Ingestion schedule binding."},
            "owners": {"type": "array", "items": {"type": "string"}},
            "created_by": {"type": "string"},
            "modified_by": {"type": "string"},
        },
    },
    "ViewConfigInput": {
        "type": "object",
        "required": ["name", "module", "config"],
        "description": "Create/update a module view: grid/list layout for the module's UI.",
        "properties": {
            "name": {"type": "string"},
            "module": {"type": "string"},
            "type": {"type": "string"},
            "isDefault": {"type": "boolean"},
            "config": {"type": "object", "description": "Layout: `rows` of columns, `metadata` (template titles), paging."},
            "viewOptions": {"type": "object"},
        },
    },
    "MCPHostRequest": {
        "type": "object",
        "required": ["mcp_configuration", "metadata", "tools"],
        "description": "Host a connector's operations as MCP tools (`POST /mcp/add/tools`). Tool rows are keyed globally by name -- duplicates across servers silently drop. Requires the connector definition and a configuration first.",
        "properties": {
            "mcp_configuration": {"type": "object", "required": ["name", "uuid"],
                                  "properties": {"name": {"type": "string"}, "uuid": {"$ref": "#/components/schemas/UUID"}}},
            "config": {"type": "object", "description": "Connector configuration values for the hosted tools."},
            "metadata": {"type": "object", "required": ["name", "label", "version", "connectorName"],
                         "properties": {
                             "name": {"type": "string"},
                             "label": {"type": "string"},
                             "version": {"type": "string"},
                             "connectorName": {"type": "string"},
                         }},
            "tools": {"type": "array",
                      "items": {"type": "object", "required": ["operation"],
                                "properties": {
                                    "operation": {"type": "string", "description": "Connector operation to expose."},
                                    "title": {"type": "string"},
                                    "description": {"type": "string"},
                                    "category": {"type": "string"},
                                    "visible": {"type": "boolean"},
                                    "enabled": {"type": "boolean"},
                                    "parameters": {"type": "object"},
                                    "addTool": {"type": "boolean"},
                                }},
                      "description": "One row per operation to host."},
        },
    },
    "MCPToolsUpdateRequest": {
        "type": "object",
        "required": ["uuid", "metadata"],
        "description": "Update a hosted MCP server's tool set (`PUT /mcp/tools/{mcp_config_uuid}`): `tools` re-declares hosted rows, `remove_tools` unhosts by operation name.",
        "properties": {
            "uuid": {"$ref": "#/components/schemas/UUID"},
            "metadata": {"type": "object", "required": ["name", "connectorName", "label", "version"],
                         "properties": {
                             "name": {"type": "string"},
                             "connectorName": {"type": "string"},
                             "label": {"type": "string"},
                             "version": {"type": "string"},
                         }},
            "config": {"type": "object"},
            "tools": {"type": "array", "items": {"type": "object"}},
            "remove_tools": {"type": "array", "items": {"type": "string"},
                             "description": "Operation names to unhost."},
        },
    },
    "MCPExportRequest": {
        "type": "array",
        "description": "Servers to export (`POST /mcp/config/export`): one `{uuid}` object per registered server.",
        "items": {"type": "object", "required": ["uuid"],
                  "properties": {"uuid": {"$ref": "#/components/schemas/UUID"}}},
    },
})

# Standard query parameters reused across /api/3/*
COMMON_QPARAMS = [
    {"name": "$limit", "in": "query", "description": "Max records per page. Default 30, max 5000.",
     "schema": {"type": "integer", "default": 30, "minimum": 1, "maximum": 5000}},
    {"name": "$page", "in": "query", "description": "1-indexed page number.",
     "schema": {"type": "integer", "default": 1, "minimum": 1}},
    {"name": "$orderby", "in": "query", "description": "Sort field; prefix `-` for descending. Example: `-createDate`.",
     "schema": {"type": "string", "example": "-createDate"}},
    {"name": "$relationships", "in": "query", "description": "Controls whether linked modules are included in the response. When `true`, related collections (e.g. an alert's `tasks`, `indicators`, `assets`) are populated. When `false` (default), those collections are left out of the response entirely - not returned as empty arrays. Single-value links like `severity`, `status`, `createUser` are always returned as full record objects regardless of this flag.",
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


# Placeholder UUIDs used both in PATHS examples below and in the
# CURATED_EXAMPLES dict (defined up here so both sections can reference them).
_UUID = "f3a2c1de-9b40-4ed3-9f7c-2e1d8a5b3c91"
_UUID2 = "a7e54b80-1234-4cab-8b2f-9d11f3b6a2c4"
_PB_UUID = "c0d3e8a1-7b2f-4a91-b85e-7d2e1f3a4b56"
_FILE_UUID = "1f9a3c4d-5e6b-4789-a012-3b4c5d6e7f80"

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
        "summary": "Retrieve license details",
        "description": (
            "Returns the current license state for the cluster (or a specific node, with `node_id`). "
            "Authenticated equivalent of the `POST /api/public/license` `get_info` flow, but reports "
            "deployed-license state (`remaining_days`, `expired_nodes`, per-node max users, "
            "issue/expiry dates) rather than parsing an unsubmitted key.\n\n"
            "Some builds answer a generic 400 when the auth service is unhappy; callers that just "
            "need basic build info should prefer `GET /api/version` instead."
        ),
        "parameters": [
            {"name": "param", "in": "query", "required": False,
             "schema": {"type": "string", "enum": ["license_details"]},
             "description": "Set to `license_details` to return the full per-node license report. "
                            "Omitted -> compact summary."},
            {"name": "node_id", "in": "query", "required": False,
             "schema": {"type": "string"},
             "description": "Limit the response to one node. Pass `SELF` to mean the node serving "
                            "the request (added in 7.0.0)."},
        ],
        "responses": {"200": _resp("License details.", example={
            "expired": False, "expired_nodes": [], "remaining_days": 180,
            "details": {"is_distributed": False, "role": ["master"], "entitlements": {}},
            "nodes": {"<node-id>": {
                "message": "License Details: Max Users: 10, Expiring on: 2026-12-01, Issued for 180 days",
                "details": {"total_users": 10, "remaining_users": 9, "total_days": 180,
                             "remaining_days": 180, "customer_name": "abc",
                             "is_distributed": False, "entitlements": {}, "role": ["master"]},
                "node": {"nodeId": "<node-id>", "nodeName": "fortisoar.localhost",
                          "status": "active", "role": "primary", "currentState": "primary server"},
            }},
        })},
    },
    "post": {
        "tags": ["System"],
        "summary": "Deploy a license (authenticated)",
        "description": (
            "Authenticated license deployment. Requires a **previously valid** license to be "
            "currently active - this form is intended for renewals / replacements, not first-time "
            "activation. For first-time activation on a fresh appliance use the unauthenticated "
            "`POST /api/public/license` with `action: deploy_license`.\n\n"
            "Body carries the raw `license_key` (the contents of the `.lic` file). Returns 200 OK "
            "on success.\n\n"
            "A FortiFlex activation token is **rejected** here (live-verified: 400 `The server "
            "encountered an error while handling the request`); deploy FortiFlex entitlements "
            "through `POST /api/public/license` with `action: install_flex_license` and the token "
            "under `data.license_token` instead."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {
                "type": "object",
                "required": ["license_key"],
                "properties": {
                    "license_key": {"type": "string",
                                    "description": "Raw contents of the license file."},
                },
            },
            "example": {"license_key": "<license-file-contents>"},
        }}},
        "responses": {"200": _resp("License deployed.")},
    },
}

PATHS["/api/public/license"] = {
    "post": {
        "tags": ["System"],
        "summary": "Public license API (deploy / status / info)",
        "description": (
            "One endpoint with three behaviors keyed off "
            "the `action` discriminator:\n\n"
            "- `action: deploy_license` - install a license on a fresh / unlicensed appliance. "
            "  Body: `license_key`, `nodeId`, `action`. Returns 200 OK on success. This is the "
            "  first-time-activation path - once a valid license is deployed, prefer the "
            "  authenticated `POST /api/auth/license` for renewals.\n"
            "- `action: get_status` - poll deployment progress. Body: `action` (+ optional "
            "  `nodeId` for per-node status; omit for cluster-wide). Returns `depl_status` "
            "  (e.g. `finished`) plus either `depl_message` (cluster summary) or `depl_info` "
            "  (`source`, `user_id`, `ws_session_id`, `depl_start_time`) for a single node.\n"
            "- `action: get_info` - parse a license key **without** deploying it. Body: "
            "  `license_key`, `action`. Returns `serial_no`, `expiry_time`, `hardware_key`, "
            "  `max_users`, `entitlements`, `type`, `edition`. For Subscription-type licenses, "
            "  `max_users` / `expiry_time` are only populated after deployment (they're fetched "
            "  from FDN at activation time)."
        ),
        "security": [],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string",
                               "enum": ["deploy_license", "get_status", "get_info"],
                               "description": "Discriminator. See description for the body shape each action expects."},
                    "license_key": {"type": "string",
                                    "description": "Raw license file contents. Required for `deploy_license` and `get_info`."},
                    "nodeId": {"type": "string",
                               "description": "Target node id. Required for `deploy_license`; optional for "
                                              "`get_status` (omit -> cluster-wide). Discoverable via "
                                              "`GET /api/auth/license?param=license_details` "
                                              "(`nodes.<id>.node.nodeId`)."},
                },
            },
            "examples": {
                "deploy_license": {"summary": "Deploy on a fresh appliance",
                                    "value": {"action": "deploy_license",
                                              "license_key": "<license-file-contents>",
                                              "nodeId": "0961991714b6089a1d31983ea76f869e"}},
                "get_status": {"summary": "Poll deployment progress",
                                "value": {"action": "get_status",
                                          "nodeId": "0961991714b6089a1d31983ea76f869e"}},
                "get_info": {"summary": "Parse a key without deploying",
                              "value": {"action": "get_info",
                                        "license_key": "<license-file-contents>"}},
            },
        }}},
        "responses": {"200": _resp("Action-specific payload. See description.", example={
            "depl_status": "finished",
            "depl_info": {"source": "192.168.56.1", "user_id": None,
                           "ws_session_id": None, "depl_start_time": "2026-12-23T12:23:30.771975"},
        })},
    },
}

PATHS["/api/version"] = {
    "get": {
        "tags": ["System"],
        "summary": "Build version",
        "description": "Cheap probe for the build version; also a quick health check.",
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
        "summary": "Current actor (user, appliance, or API key)",
        "description": (
            "Returns the calling principal as a unified Actor record. The `@type` "
            "says which subtype answered: a JWT user gets `Person` (profile fields "
            "-- for user-only detail look up `GET /api/3/people/{uuid}` with the "
            "`uuid` from this response); an appliance/agent gets `Appliance`; an "
            "API-key principal gets `ApiKey` (`name` is the key user's loginid, "
            "`userId` its das user uuid -- type-9 key users have **no** People "
            "record, so `GET /api/3/people?userId=<userId>` comes back empty, and "
            "`GET /api/auth/users?uuid=` is admin-only: 403 under an API key). "
            "Answers for any authenticated key -- even one with no roles "
            "(live-verified) -- since it is the principal's own record. "
            "Use this when code needs to work uniformly across both auth modes."
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
                "description": f"Returns a single {singular} record by uuid. Add `?$relationships=true` to include the record's linked modules (omitted by default).",
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
                "description": f"Soft-deletes the {singular} (if the module is softDeleteable) or hard-deletes otherwise. Returns 204 on success.",
                "responses": {"204": {"description": "Deleted."}, "404": _err(404, "Not found.")},
            },
        },
    }


# Generic CRUD (templated)
PATHS.update(_record_path_ops("alerts", "Alert", tag="Alerts", singular="alert"))
PATHS.update(_record_path_ops("incidents", "Incident", tag="Incidents", singular="incident"))
PATHS.update(_record_path_ops("tasks", "Task", tag="Tasks", singular="task"))
PATHS.update(_record_path_ops("comments", "Comment", tag="Comments", singular="comment"))

# The parent-scoped sub-collection is GET-only on FSR 7.6.x (POST returns 405
# `Method Not Allowed (Allow: GET)` - verified live). To create a comment
# scoped to a parent, POST /api/3/comments with the parent module's
# relationship array, e.g. {"content": "...", "incidents": ["/api/3/incidents/<uuid>"]}.
PATHS["/api/3/{module}/{recordId}/comments"] = {
    "parameters": [
        {"name": "module", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Plural module name (e.g. `alerts`, `incidents`, `tasks`)."},
        {"name": "recordId", "in": "path", "required": True,
         "schema": {"$ref": "#/components/schemas/UUID"},
         "description": "uuid of the parent record."},
    ],
    "get": {
        "tags": ["Comments"],
        "summary": "List comments on a record",
        "description": (
            "Returns comments linked to the parent record. Equivalent to "
            "`GET /api/3/comments?<module>.uuid=<recordId>` but cheaper - the "
            "server scopes the query for you.\n\n"
            "**Create** is *not* allowed on this path (405). Use "
            "`POST /api/3/comments` with the parent IRI in the matching "
            "relationship array (e.g. `{\"content\": \"...\", \"incidents\": "
            "[\"/api/3/incidents/<uuid>\"]}`)."
        ),
        "parameters": COMMON_QPARAMS,
        "responses": {"200": _resp("Hydra collection of comments.", ref="HydraCollection")},
    },
}

# Generic templated record CRUD - documents the pattern
# cyops-api refuses an API key's create/update of an Actor (people,
# appliances, api_keys) whatever the key's role; measured on 8.0.0 and 8.0.1.
ACTOR_WRITE_NOTE = (
    "An API key cannot create or change `people`, `appliances` or `api_keys` records: "
    "FortiSOAR answers 403 whatever the key's role. Use a JWT for those."
)

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
        "description": ACTOR_WRITE_NOTE,
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
            "description": (
                "Ordinary field updates: send the changed fields as a flat JSON object.\n\n"
                "**Relationship add/remove without resending the whole record:** send "
                "`{\"__link\": {\"<field>\": [\"<iri-or-module:uuid>\", ...]}}` to add related "
                "records to a relationship field, or `{\"__unlink\": {\"<field>\": [...]}}` to "
                "remove them - both leave the rest of the record untouched. Each ref may be a "
                "full IRI (`/api/3/assets/<uuid>`) or `<module>:<uuid>` shorthand; a bare uuid is "
                "rejected since the related module can't be inferred. Live-verified: linking an "
                "`Asset` onto an `Alert`'s `assets` field, confirmed via `GET "
                "/api/3/alerts/<uuid>/assets`, then unlinked and reconfirmed empty. See "
                "`$relationships` above for the read side of the same relationship fields.\n\n"
                + ACTOR_WRITE_NOTE
            ),
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _resp("Updated.")}},
    "delete": {"tags": ["Records (generic)"], "summary": "Delete a record",
               "responses": {"204": {"description": "Deleted."}}},
}


# --- Bulk record ops -------------------------------------------------------

for verb, op_method, op_summary, op_desc, body_shape in [
    ("insert",     "post",   "Bulk insert",
     "Documented bulk-insert path. **Broken on FSR 7.6.x** with a bare array body. On 8.0.0 it works "
     "when the rows arrive wrapped in a `data` key (same envelope as `/api/ingest-feeds/*`); the bare "
     "array still 400s with `TypeError`. Unlike the feed paths, insert does NOT skip on-create "
     "playbook triggers.", "data_obj"),
    ("update",     "put",    "Bulk update",
     "Documented bulk-update path. **Broken on FSR 7.6.x** with a bare array body. On 8.0.0 it works "
     "when the row objects (each carrying `@id`) arrive wrapped in a `data` key; the bare array still "
     "400s with `HttpException`.", "data_obj"),
    ("delete",     "delete", "Bulk delete",
     "Documented bulk-delete path. **Broken on 7.6.x and 8.0.0:** every body shape probed (bare array "
     "of IRIs, array of uuids, `data`-wrapped objects, query param) returns 400 `TypeError: Internal "
     "Server Error`. Delete records individually via `DELETE /api/3/{collection}/{uuid}`.", "array_str"),
    ("upsert",     "post",   "Upsert by natural key",
     "Insert-or-update **a single record** keyed on the module's identifier field. Body is a JSON object, "
     "not an array - use `/api/3/bulkupsert/{moduleType}` for the array variant.", "object"),
    ("bulkupsert", "post",   "Bulk upsert",
     "Array-input version of upsert. Body must be a JSON array.", "array_obj"),
]:
    # Response codes + shapes live-verified on 8.0.0 (live_observations.json):
    # insert and upsert answer **201** (upsert with the bare written record,
    # insert with a hydra collection), update answers **200** with a hydra
    # collection. The old generic "result envelope (per-record status)" 200
    # was guesswork the wire contradicts; only bulkupsert actually returns it.
    if verb == "insert":
        responses = {
            "201": _resp("Created records: a hydra collection whose `hydra:member` rows are the "
                         "new `{moduleType}` records. (Live-verified: a clean batch answers "
                         "`201` with this collection, not a result envelope.)",
                         ref="RecordWriteCollection"),
            "200": _resp("Multi-status envelope, seen when a row is rejected: `success` rows "
                         "are the records that wrote, `failure` entries are raw error strings.",
                         ref="BulkUpsertResult"),
        }
    elif verb == "update":
        responses = {"200": _resp("Updated records: a hydra collection whose `hydra:member` "
                                  "rows are the updated `{moduleType}` records.",
                                  ref="RecordWriteCollection")}
    elif verb == "upsert":
        responses = {"201": _resp("The written record (created or updated), with the module's "
                                  "full field set.", ref="ModuleRecord")}
    else:  # bulkupsert
        responses = {
            "201": _resp("Created/updated records: a hydra collection whose `hydra:member` rows "
                         "are the written `{moduleType}` records (clean batch).",
                         ref="RecordWriteCollection"),
            "200": _resp("Multi-status envelope when a row is rejected: `success` rows are the "
                         "records that wrote, `failure` entries are raw error strings.",
                         ref="BulkUpsertResult"),
        }
    op_def = {
        "tags": ["Bulk operations"],
        "summary": op_summary,
        "description": op_desc,
        "responses": responses,
    }
    if verb == "delete":
        op_def["deprecated"] = True  # routed but broken on every probed build; spec_health skips it
    if body_shape == "array_obj":
        schema = {"type": "array", "items": {"type": "object"}}
    elif body_shape == "array_str":
        schema = {"type": "array", "items": {"type": "string"}}
    elif body_shape == "data_obj":
        schema = {"type": "object", "required": ["data"], "properties": {
            "data": {"type": "array", "items": {"type": "object"},
                     "description": "Rows keyed by the module's field names; update rows "
                                    "must each carry an `@id`."}}}
    else:  # object
        schema = {"type": "object"}
    op_def["requestBody"] = {"required": True, "content": {"application/json": {"schema": schema}}}
    PATHS[f"/api/3/{verb}/{{moduleType}}"] = {
        "parameters": [{"name": "moduleType", "in": "path", "required": True, "schema": {"type": "string"}, "example": "alerts"}],
        op_method: op_def,
    }

_INGEST_BODY = {"required": True, "content": {"application/json": {
    "schema": {"type": "object", "required": ["data"], "properties": {
        "data": {"type": "array", "items": {"type": "object"},
                 "description": "Rows keyed by the module's field names."}}},
    "example": {"data": [{"value": "evil.example.com"}]}}}}

PATHS["/api/ingest-feeds/indicators"] = {
    "post": {
        "tags": ["Bulk operations"],
        "summary": "Threat-intel feed bulk ingest",
        "description": (
            "Bulk-insert TI indicators. Distinct from `POST /api/3/insert/indicators`: the feed-ingest "
            "path bypasses on-create playbook triggers (intentional for high-volume feeds). The body "
            "wraps the rows in `data`; rows that match an existing record on the module's unique "
            "key update it. This is `POST /api/ingest-feeds/{module}` with `module` = `indicators`."
        ),
        "requestBody": _INGEST_BODY,
        "responses": {"200": _resp("Ingest result.", "FeedIngestResult")},
    },
}

PATHS["/api/ingest-feeds/{module}"] = {
    "parameters": [{"name": "module", "in": "path", "required": True, "schema": {"type": "string"},
                    "example": "threat_intel_feeds",
                    "description": "Module type (`type` in `GET /api/3/model_metadatas`), e.g. "
                                   "`indicators` or `threat_intel_feeds`."}],
    "post": {
        "tags": ["Bulk operations"],
        "summary": "Feed bulk ingest into any module",
        "description": (
            "Bulk-insert rows into the module named in the path, skipping on-create playbook "
            "triggers. One SQL `INSERT ... ON CONFLICT DO UPDATE` on the module's unique key, so "
            "a row matching an existing record updates it. `threat_intel_feeds` also links "
            "related feeds.\n\n"
            "The path segment must be a real module type. There are no `observables`, "
            "`reputation`, `threatintel` or `stix-bundle` routes: those names are looked up as "
            "modules and fail with 400 `MappingException` (8.0.0 and 8.0.1). To load STIX, map "
            "each object to module rows first."
        ),
        "requestBody": _INGEST_BODY,
        "responses": {"200": _resp("Ingest result.", "FeedIngestResult"),
                      "400": {"description": "Unknown module (`MappingException`) or a row the "
                                             "database rejects (`Error: ...`)."}},
    },
}

PATHS["/api/insert-feeds/{recordType}"] = {
    "parameters": [{"name": "recordType", "in": "path", "required": True, "schema": {"type": "string"}}],
    "post": {
        "tags": ["Bulk operations"],
        "summary": "Generic feed insert",
        "description": (
            "Listed in the 7.6.5 API guide, but **not routed on 8.0.0/8.0.1**: every `recordType` "
            "404s at the router level (`No route found`). Do not confuse it with the similarly named "
            "`/api/ingest-feeds/{module}` (with a \"g\"), which is the real, working generalization of "
            "`/api/ingest-feeds/indicators`."
        ),
        "deprecated": True,
        "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object"}}}}},
        "responses": {"404": _resp("Not routed on 8.x - use `/api/ingest-feeds/{module}`.")},
    },
}

# --- TAXII 2.1 server (read-only) -----------------------------------------
# FortiSOAR exposes a non-standard TAXII layout: api-root is `/api/taxii/1/`
# (no separate discovery / api-root / status endpoints), and the objects /
# manifest envelope is `{totalItems, objects: []}` rather than the standard
# `more` / `next` cursor. POST to `objects/` is not routed on tested builds.

_TAXII_COLLECTION_UUID_PARAM = {
    "name": "uuid", "in": "path", "required": True,
    "schema": {"type": "string", "format": "uuid"},
}

PATHS["/api/taxii/1/"] = {
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "TAXII server info",
        "description": (
            "Returns the server descriptor: title, supported TAXII versions, and the maximum content "
            "length the server accepts for client uploads. This is the TAXII entry point - clients "
            "typically call this first to confirm protocol compatibility."
        ),
        "responses": {"200": _resp("TAXII server descriptor.")},
    },
}

PATHS["/api/taxii/1/collections"] = {
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "List TAXII collections",
        "description": (
            "Lists every TAXII collection the caller is allowed to see. Each entry carries `can_read` / "
            "`can_write` permissions and the media types the collection accepts.\n\n"
            "The seven default collections shipped with FortiSOAR - FortiGuard Outbreak / Phishing / "
            "Threat Intel feeds, Block List (Domain / URL / IP), and **Custom** - are all read-only. "
            "Writable collections need to be provisioned explicitly."
        ),
        "responses": {"200": _resp("Collections list.")},
    },
}

PATHS["/api/taxii/1/collections/{uuid}"] = {
    "parameters": [_TAXII_COLLECTION_UUID_PARAM],
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "Get one TAXII collection",
        "description": (
            "Returns metadata for a single TAXII collection - name, title, read/write permissions, "
            "supported media types."
        ),
        "responses": {"200": _resp("Collection descriptor.")},
    },
}

PATHS["/api/taxii/1/collections/{uuid}/objects"] = {
    "parameters": [_TAXII_COLLECTION_UUID_PARAM],
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "Fetch STIX objects from a collection",
        "description": (
            "Returns STIX 2.1 objects from the collection. The response envelope is "
            "`{totalItems, objects: []}` - a FortiSOAR-specific shape, not the standard TAXII 2.1 "
            "`more` / `next` cursor. Use `limit` + `added_after` to paginate."
        ),
        "parameters": [
            {"name": "limit", "in": "query", "schema": {"type": "integer"},
             "description": "Maximum number of objects to return."},
            {"name": "added_after", "in": "query", "schema": {"type": "string", "format": "date-time"},
             "description": "Only return objects added to the collection after this ISO-8601 timestamp."},
        ],
        "responses": {"200": _resp("Objects envelope.")},
    },
}

PATHS["/api/taxii/1/collections/{uuid}/objects/{stixId}"] = {
    "parameters": [
        _TAXII_COLLECTION_UUID_PARAM,
        {"name": "stixId", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "STIX object id (e.g. `indicator--<uuid>`)."},
    ],
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "Fetch one STIX object",
        "description": (
            "Returns the same `{totalItems, objects: []}` envelope as the collection-level `objects/` "
            "endpoint, filtered to the single object whose STIX id matches.\n\n"
            "**Known issue (FSR 7.6.5):** this route returns an empty envelope "
            "(`{totalItems: 0, objects: []}`) for every form of `stixId` we tested - bare record "
            "uuid, `indicator--<uuid>`, the listing's own `id` field, with or without `?stix=2.1`. "
            "The collection-level `objects/` endpoint works; use it and filter client-side until "
            "this is fixed upstream."
        ),
        "responses": {"200": _resp("Single-object envelope.")},
    },
}

PATHS["/api/taxii/1/collections/{uuid}/manifest"] = {
    "parameters": [_TAXII_COLLECTION_UUID_PARAM],
    "get": {
        "tags": ["Threat intel (TAXII)"],
        "summary": "Fetch the collection manifest",
        "description": (
            "Returns one entry per object in the collection - id, date added, version, media type - "
            "without the object bodies. Useful for cheap \"what's new since X\" polls before pulling "
            "full STIX content."
        ),
        "parameters": [
            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
            {"name": "added_after", "in": "query", "schema": {"type": "string", "format": "date-time"}},
        ],
        "responses": {"200": _resp("Manifest envelope.")},
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

PATHS["/api/query/{collection}/{id}/{field}"] = {
    "parameters": [
        {"name": "collection", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Module of the record, e.g. `alerts`."},
        {"name": "id", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
         "description": "uuid of the record whose links to read."},
        {"name": "field", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "A to-many relationship on the module, e.g. `indicators`. "
                        "`owners`, `files`, `userOwners` and `datasets` are excluded."},
        {"name": "$limit", "in": "query", "required": False, "schema": {"type": "integer"}},
        {"name": "$page", "in": "query", "required": False, "schema": {"type": "integer"}},
    ],
    "post": {
        "tags": ["Query"],
        "summary": "Query the records linked to one record",
        "description": (
            "Returns the records on the other side of one record's to-many relationship (an alert's "
            "`indicators`, an incident's `alerts`), narrowed by the usual Query body. The body needs both "
            "`logic` and `filters`: an empty body is a 400. Page with `$limit`/`$page`.\n\n"
            "There is no route that runs a saved query by id (`POST /api/query/{collection}/{queryId}` 404s). "
            "To run one, read it from `/api/3/user_queries` or `/api/3/system_queries` and post its `query` "
            "to `POST /api/query/{collection}`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["logic", "filters"], "properties": {
                "logic": {"type": "string", "enum": ["AND", "OR"]},
                "filters": {"type": "array", "items": {"type": "object"}},
                "sort": {"type": "array", "items": {"type": "object"}},
            }},
            "example": {"logic": "AND", "filters": []},
        }}},
        "responses": {"200": _resp("Hydra collection of the linked records.", ref="HydraCollection")},
    },
}

PATHS["/api/3/user_queries"] = {
    "post": {
        "tags": ["Query"],
        "summary": "Save a user query",
        "description": (
            "Persists a Query body. FortiSOAR has no run-by-id route: to run it, read the record "
            "and post its `query` to `POST /api/query/{collection}`. "
            "Each saved query is scoped to one module (`models` IRI). System-shipped equivalents "
            "live under `/api/3/system_queries`; ad-hoc one-shots under `/api/3/queries`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {
                "type": "object",
                "required": ["name", "models", "query"],
                "properties": {
                    "name": {"type": "string", "description": "Display name (unique per user)."},
                    "models": {"type": "string",
                               "description": "Model IRI - `/api/3/model_metadatas/<uuid>` for the target module."},
                    "query": {"type": "object",
                              "description": "Same body grammar as `POST /api/query/{collection}` (`logic`, `filters`, `limit`, `sort`, ...).",
                              "properties": {
                                  "logic": {"type": "string", "enum": ["AND", "OR"]},
                                  "filters": {"type": "array", "items": {"type": "object"}},
                                  "limit": {"type": "integer"},
                                  "sort": {"type": "array", "items": {"type": "object"}},
                              }},
                },
            },
            "example": {
                "name": "Open alerts (recent)",
                "models": "/api/3/model_metadatas/<alert-uuid>",
                "query": {"logic": "AND", "limit": 5,
                          "filters": [{"field": "status.itemValue", "operator": "neq", "value": "Closed"}]},
            },
        }}},
        "responses": {"201": _resp("Persisted query record.")},
    },
}

PATHS["/api/search"] = {
    "post": {
        "tags": ["Query"],
        "summary": "Global Elasticsearch search",
        "description": (
            "Cross-module text search backed by Elasticsearch. **Min 3 chars** enforced. "
            "Team / RBAC scoped automatically (your accessible team IRIs are appended to "
            "the ES filter). Use this for global-search-bar UX; for deterministic "
            "per-entity filtering prefer `POST /api/query/<resourceShortName>`.\n\n"
            "**Diagnostic gotcha:** this route returns `400 TypeError` when the "
            "downstream search service is unhealthy, not when the request body is "
            "wrong. If you see that error with a well-formed body, the search "
            "subsystem on the appliance needs attention - the API surface itself is "
            "fine."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["q", "index"], "properties": {
                "q": {"type": "string", "minLength": 3,
                      "description": "Search term. Server enforces a min-3-character rule and rejects shorter strings."},
                "index": {"type": "array", "items": {"type": "string"}, "minItems": 1,
                          "example": ["alerts", "incidents"],
                          "description": "Plural module names to search across. The server intersects this with the caller's accessible types."},
                "size": {"type": "integer", "default": 30, "description": "Max hits to return."},
                "offset": {"type": "integer", "default": 0, "description": "0-indexed offset for paging."},
                "sort": {"type": "string", "default": "_score",
                         "description": "ES sort spec. Defaults to relevance."},
                "searchType": {"type": "string", "default": "_default"},
                "modifyDateGte": {"type": "integer",
                                  "description": "Lower bound on `modifyDate` (epoch). Omit or 0 for unbounded."},
                "modifyDateLte": {"type": "integer",
                                  "description": "Upper bound on `modifyDate` (epoch). Omit or 0 for unbounded."},
            }},
            "example": {"q": "fortinet phishing", "index": ["alerts", "incidents"], "size": 30},
        }}},
        "responses": {"200": {
            "description": "Search payload.",
            "content": {"application/json": {"schema": {
                "type": "object",
                "properties": {
                    "totalItems": {"type": "integer",
                                   "description": "ES `total.value` from the underlying search hit count."},
                    "results": {"type": "array",
                                "description": "ES `hits` array (raw - each entry has `_index`, `_id`, `_score`, `_source`).",
                                "items": {"type": "object"}},
                    "context_code": {"type": "integer",
                                     "description": "Internal status from the search consumer. `200` on success."},
                },
            }}},
        }},
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
               "description": "Documented Fortinet recipe to **stop automatic purging of audit logs**. Returns 200.",
               "responses": {"200": _resp("Disabled.")}},
}


# --- Notifications ---------------------------------------------------------
# Per-user system (bell-icon) notifications. Note the non-standard
# `/api/rule/` namespace and that the list endpoint is POST, not GET.

PATHS["/api/rule/api/system-notification/notifications/"] = {
    "post": {
        "tags": ["Notifications"],
        "summary": "List the caller's notifications",
        "description": (
            "Returns the caller's system (bell-icon) notifications, newest "
            "first. **The list is POST, not GET** - the UI posts to this "
            "endpoint. Filtering is via query parameters only; the request body "
            "is empty. Returns a Hydra envelope (`hydra:member` + "
            "`hydra:totalItems` + paging links). Each row is a `Notification` "
            "(`uuid`, `content` as HTML, `entity_type`, `read`, ...). Use `uuid` "
            "as the row identity (`id_iri`/`record_type` stay null)."
        ),
        "parameters": [
            {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
            {"name": "read", "in": "query", "schema": {"type": "boolean"},
             "description": "Filter by read state - `true` for read only, `false` for unread only, omit for all."},
            {"name": "entity_type__in", "in": "query", "schema": {"type": "string"},
             "description": "Comma-joined source entity types to restrict to (e.g. `comments,approvals`)."},
            {"name": "search", "in": "query", "schema": {"type": "string"},
             "description": "Free-text filter over notification `content`."},
            {"name": "limit", "in": "query", "schema": {"type": "integer"},
             "description": "Page size. Omit to follow `hydra:nextPage` until exhausted."},
            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
        ],
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {},
                       "description": "No request body - this is a POST-list endpoint; filter via the query parameters above."},
            "example": {},
        }}},
        "responses": {"200": _resp("Hydra envelope of Notification rows.")},
    },
}

PATHS["/api/rule/api/system-notification/purge/"] = {
    "post": {
        "tags": ["Notifications"],
        "summary": "Bulk-purge notifications (asynchronous)",
        "description": (
            "Kicks off an **asynchronous** server-side purge and returns "
            "immediately with an ack (`result` + `status`); rows are removed in "
            "the background, so a following count may still report the old total "
            "briefly. Scope via `read`: `true` purges only already-read "
            "notifications (the UI's \"clear read\" default), `false` purges "
            "unread, omit purges all. **There is no undo.**"
        ),
        "parameters": [
            {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
            {"name": "read", "in": "query", "schema": {"type": "boolean"},
             "description": "Scope - `true` purges read, `false` purges unread, omit purges all."},
        ],
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {},
                       "description": "No request body - scope via the `read` query parameter."},
            "example": {},
        }}},
        "responses": {"200": _resp("Purge ack.")},
    },
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
        "tags": ["Playbook runs"],
        "summary": "List recent playbook runs",
        "description": (
            "Hydra-paged list of recent playbook execution logs. **Recent** here means runs that have not "
            "yet been moved to historical storage by the Playbook Log Movement task (runs every 15 minutes "
            "for completed playbooks, 60 minutes for failed/terminated; configurable in System Configuration).\n\n"
            "For runs older than that, use `GET /api/wf/api/historical-workflows/`. To combine both stores in "
            "a single query, use `POST /api/wf/api/query/workflow_logs/?logs=all`.\n\n"
            "Common patterns:\n\n"
            "- `task_id=<uuid>` (with `parent_wf__isnull=True`) - look up the run created by a trigger POST, "
            "  skipping sub-playbook children.\n"
            "- `ordering=-modified` + `limit=1` - newest run first.\n"
            "- `template_iri=/api/3/workflows/<uuid>` - runs of a specific playbook.\n"
            "- `records=/api/3/alerts/<uuid>` - runs executed against a specific record.\n"
            "- `status=failed&created_after=2024-11-08&created_before=2024-11-10` - failed runs in a window.\n"
            "- `tags_include=ingestion,critical&tags_exclude=system` - tag allow/deny lists.\n\n"
            "Each `hydra:member` entry has `status` (one of `incipient`, `active`, `pending`, `running`, "
            "`finished`, `failed`, `awaiting`, `skipped`, `terminated`, `paused`) and `@id` - the trailing "
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
        "tags": ["Playbook runs"],
        "summary": "Recent run detail",
        "description": (
            "Full execution record for one recent playbook run. `result` is a dict keyed by step UUID with "
            "each step's output - this is where playbook return values live. Use after polling the list "
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
        "tags": ["Playbook runs"],
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
        "tags": ["Playbook runs"],
        "summary": "List historical playbook runs",
        "description": (
            "Hydra-paged list of playbook runs that have been moved to historical storage (added in 7.6.1). "
            "Same filter grammar as `/api/wf/api/workflows/` with one nit: the parent-only filter is named "
            "`parent__isnull` here (vs `parent_wf__isnull` on the recent endpoint).\n\n"
            "Use `GET /api/wf/api/workflows/count?logs=all` for a combined count across recent + historical."
        ),
        "parameters": _WF_LIST_PARAMS + [
            {"name": "parent__isnull", "in": "query", "schema": {"type": "boolean"},
             "description": "Historical-only equivalent of `parent_wf__isnull` - `True` filters out sub-playbook children."},
        ],
        "responses": {"200": _resp("Hydra collection of historical runs.")},
    },
}

PATHS["/api/wf/api/historical-workflows/{pk}/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Historical workflow pk (trailing segment of `@id`)."}],
    "get": {
        "tags": ["Playbook runs"],
        "summary": "Historical run detail",
        "description": (
            "Detail view for one historical playbook run. Shape mirrors `/api/wf/api/workflows/{pk}/` - "
            "`result` per-step output, `template_iri` to the source playbook, `created`/`modified` timestamps, "
            "`env` snapshot."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"200": _resp("Historical run detail.")},
    },
}

PATHS["/api/wf/api/query/workflow_logs/"] = {
    "post": {
        "tags": ["Playbook runs"],
        "summary": "Query playbook logs (recent + historical)",
        "description": (
            "POST-body query against the playbook log store. `?logs=all` (default) combines recent and "
            "historical; `?logs=recent` or `?logs=historical` restrict to one source.\n\n"
            "If the request body is `{\"query\": {}}` (or any non-empty body), filtering uses the body's "
            "grammar (`logic`, `filters`, `sort`, `aggregates`) - same shape as `POST /api/query/{collection}`. "
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
    "get": {"tags": ["Playbook runs"], "summary": "Workflow count",
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
    ("resume", "Resume a paused workflow (status=`paused`; for `awaiting` manual-input runs use `POST {pk}/wfinput_resume/` instead)."),
    ("approval", "Approval-step shortcut. Body shape unverified; expected `{decision, comment}`."),
]:
    _schema, _example = _WF_ACTION_BODIES[action]
    PATHS[f"/api/wf/api/workflows/{{pk}}/{action}/"] = {
        "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"}}],
        "post": {"tags": ["Playbook runs"], "summary": f"Workflow {action}", "description": desc,
                 "requestBody": {"required": False, "content": {"application/json": {
                     "schema": _schema, "example": _example,
                 }}},
                 "responses": {"200": _resp("Action result.")}},
    }

# Retry is a **GET** on 8.0.0 (the guide's POST answers 405 "Method POST not
# allowed"); it re-queues the run from its failed step and answers
# `{task_id, result: "workflow retry queued..."}`.
PATHS["/api/wf/api/workflows/{pk}/retry/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"}}],
    "get": {"tags": ["Playbook runs"], "summary": "Retry a failed workflow from the failed step",
            "description": (
                "Re-queues a failed run from the step it failed on. **GET, not POST** on 8.0.0: "
                "the API guide's POST answers 405 `Method \"POST\" not allowed.` The response "
                "carries a fresh `task_id` for the retried run."
            ),
            "responses": {"200": _resp("Retry queued.", example={
                "task_id": "3c5e5b9d-1fde-41e7-9f53-ba8c4ac979ce",
                "result": "workflow retry queue"})}},
}

PATHS["/api/wf/api/jinja-editor/"] = {
    "post": {
        "tags": ["Playbook runs"],
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
    "post": {"tags": ["Playbook runs"], "summary": "List pending manual inputs",
             "description": "GET on this path returns 405 - must be POST.\n\nEach `hydra:member` carries `id` (the `manual_input_id` for the resume), `step_id` (the execution-step id - the only honest link to a run, since `workflow` is an *encrypted* token, not the run pk), `type` (`InputBased`/`DecisionBased`), and `title`. The list omits `response_mapping` (the buttons) - fetch that via `retrieve_wfinput`.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {},
             }}},
             "responses": {"200": _resp("Collection of pending inputs.")}},
}

# retrieve_wfinput: full record for one pending input, incl. response_mapping.
PATHS["/api/wf/api/manual-wf-input/{pk}/retrieve_wfinput/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "manual_input_id (`list_wfinput[].id`)."}],
    "post": {"tags": ["Playbook runs"], "summary": "Retrieve one pending manual input (with buttons)",
             "description": "Returns the full manual-input record including `response_mapping.options[]` (the buttons and each option's `step_iri`). `list_wfinput` omits these, so you need this call to know which option to send when resuming.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {}}}},
             "responses": {"200": _resp("Manual-input record with response_mapping.")}},
}

# The REAL resume path for an `awaiting` (manual-input) run. Verified live
# end-to-end 2026-05-29: the run advances to `finished` afterward.
# CORRECTION: an earlier note here called this a decoy and claimed
# `PUT /api/wf/api/manual-wf-input/{id}/` was canonical. That is WRONG -
# the PUT returns 200 but does NOT advance the run. wfinput_resume is the
# path the FortiSOAR UI and the e2e runner both use.
PATHS["/api/wf/api/workflows/{pk}/wfinput_resume/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Integer workflow-RUN pk (from the run record `@id`)."}],
    "post": {
        "tags": ["Playbook runs"],
        "summary": "Resume an awaiting manual-input gate (advances the run)",
        "description": (
            "Submit a human's input + chosen button to a paused `awaiting` run and advance it. "
            "The chosen button is conveyed via its `step_iri` (the next step it routes to), taken from "
            "`retrieve_wfinput`'s `response_mapping.options[]`. Correlate the gate to the run by id: the run's "
            "awaiting execution-step ids (`GET {pk}/?step_detail=true`) ∩ `list_wfinput[].step_id`.\n\n"
            "For `is_approval` gates also send `approved: <bool>`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["input", "step_iri", "step_id", "manual_input_id"],
                       "properties": {
                           "input": {"type": "object", "description": "Submitted inputVariable values, keyed by name."},
                           "step_iri": {"type": "string", "description": "Chosen option's step_iri (the branch to take)."},
                           "step_id": {"type": "integer", "description": "Execution-step id of the awaiting gate."},
                           "manual_input_id": {"type": "integer", "description": "list_wfinput[].id."},
                       }},
            "example": {"input": {"ip_address": "1.1.1.1", "reason": "approved"},
                        "step_iri": "/api/3/workflow_steps/11bbde6b-7afd-5460-97fc-cf7eb96844dc",
                        "step_id": 5704059, "manual_input_id": 411},
        }}},
        "responses": {"200": _resp("Resume accepted; run advances.",
                                   example={"task_id": "…", "message": "Awaiting Playbook resumed successfully."})},
    },
}

# Documented for completeness: this PUT exists and 200s but does NOT
# advance an awaiting run - use wfinput_resume instead.
PATHS["/api/wf/api/manual-wf-input/{pk}/"] = {
    "parameters": [{"name": "pk", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "manual_input_id (`list_wfinput[].id`)."}],
    "put": {
        "tags": ["Playbook runs"],
        "summary": "Update a manual-input record (does NOT resume the run)",
        "description": (
            "Returns 200 and updates the record, but **does not advance an `awaiting` run** - a common trap. "
            "To actually resume, use `POST /api/wf/api/workflows/{pk}/wfinput_resume/`. Verified live: "
            "PUT here left the run in `awaiting`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["workflow"], "properties": {
                "workflow": {"type": "integer", "description": "Numeric run id (from `retrieve_wfinput`)."},
                "input": {"type": "object"}}},
            "example": {"workflow": 142560, "input": {}}}}},
        "responses": {"200": _resp("Record updated (run NOT advanced)."),
                      "400": {"description": "`{\"workflow\": [\"This field is required.\"]}`"}},
    },
    "delete": {
        "tags": ["Playbook runs"],
        "summary": "Abandon/cancel a pending manual input",
        "description": (
            "Removes the waiting input - the paused playbook step is "
            "abandoned (there is no undo). The PUT above updates the "
            "record's contents; this DELETE removes it entirely. 204 on "
            "success."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"204": _resp("Deleted.")},
    },
}

# --- Scheduled tasks ------------------------------------------------------
# The workflow engine's cron-driven periodic-task scheduler. Each row runs a
# playbook on a schedule; the row `id` is a per-request Fernet token that
# rotates between calls, so non-immediate use resolves by `name` (the list
# endpoint returns every row).

_PATH_PARAM_ID_SCHEDULED = {
    "name": "id", "in": "path", "required": True, "schema": {"type": "string"},
    "description": (
        "Per-request Fernet token (it decrypts to a stable primary key, but the "
        "token itself rotates on every call). Only safe to use immediately after "
        "the GET/POST that produced it. For any later use, re-resolve the task by "
        "`name` via `GET /api/wf/api/scheduled/`."
    ),
}

PATHS["/api/wf/api/scheduled/"] = {
    "get": {
        "tags": ["Scheduled tasks"],
        "summary": "List periodic tasks",
        "description": (
            "Returns every scheduled periodic task - platform-shipped schedules "
            "(Reclaim Disk Space, Purge Executed Playbook Logs, Archive Data) plus "
            "user-created playbook schedules. Send `format=json` with `offset=0` "
            "and `limit=2147483647` for an unbounded fetch in one call. Each row "
            "carries a nested `crontab` (`minute`/`hour`/`day_of_week`/"
            "`day_of_month`/`month_of_year`/`timezone`) and `kwargs` (`wf_iri`, "
            "`exit_if_running`, `timezone`, `utcOffset`); the server fills `task`, "
            "`schedule_id`, `crontab.id`, and `kwargs.name`/`description`/`auth`/"
            "`schedule_entry_name`. Resolve any non-immediate use by `name` - the "
            "row `id` is a per-request Fernet token that rotates."
        ),
        "parameters": [
            {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
            {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
            {"name": "limit", "in": "query", "schema": {"type": "integer"},
             "description": "Page size. Send `2147483647` for an unbounded single-call fetch."},
        ],
        "responses": {"200": _resp("Hydra envelope of periodic-task rows.")},
    },
    "post": {
        "tags": ["Scheduled tasks"],
        "summary": "Create a periodic task",
        "description": (
            "Creates a periodic task that runs a playbook on a cron schedule. The "
            "body is a periodic-task record with a nested `crontab` (5-field cron + "
            "`timezone`) and `kwargs.wf_iri` (the workflow IRI - resolve a "
            "playbook name with `GET /api/3/workflows/?name=<playbook>`). The "
            "server fills `task`, `schedule_id`, `crontab.id`, and the "
            "`kwargs.name`/`description`/`auth`/`schedule_entry_name` fields. "
            "Returns the created record (its `id` is a fresh Fernet token)."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "required": ["name", "crontab", "kwargs", "enabled"],
                       "properties": {
                           "name": {"type": "string", "description": "Schedule display name (the server also uses it as the task description)."},
                           "crontab": {"type": "object", "description": "5-field cron map plus `timezone`.",
                                       "properties": {
                                           "minute": {"type": "string", "example": "7"},
                                           "hour": {"type": "string", "example": "2"},
                                           "day_of_week": {"type": "string", "example": "*"},
                                           "day_of_month": {"type": "string", "example": "*"},
                                           "month_of_year": {"type": "string", "example": "*"},
                                           "timezone": {"type": "string", "example": "UTC"},
                                       }},
                           "kwargs": {"type": "object", "description": "Workflow binding and runtime options.",
                                      "properties": {
                                          "wf_iri": {"type": "string", "description": "Workflow IRI (`/api/3/workflows/<uuid>`)."},
                                          "exit_if_running": {"type": "boolean", "default": True,
                                                              "description": "Skip a fire if the previous run is still active (prevents overlap)."},
                                          "timezone": {"type": "string", "default": "UTC"},
                                          "utcOffset": {"type": "string", "description": "Display hint like `UTC+00:00`; the crontab `timezone` is what the scheduler honours."},
                                      }},
                           "expires": {"type": "string", "nullable": True},
                           "start_time": {"type": "string", "nullable": True},
                           "enabled": {"type": "boolean", "default": True},
                       }},
        }}},
        "responses": {"201": _resp("The created periodic-task record.")},
    },
}

PATHS["/api/wf/api/scheduled/{id}/"] = {
    "parameters": [_PATH_PARAM_ID_SCHEDULED],
    "put": {
        "tags": ["Scheduled tasks"],
        "summary": "Replace a periodic task (full-record PUT)",
        "description": (
            "Full-record PUT (no PATCH). To toggle `enabled`, read the current "
            "row via `GET /api/wf/api/scheduled/`, flip the flag, and PUT the "
            "whole record back. The `{id}` is a per-request Fernet token - use "
            "the `id` from a fresh GET immediately before this PUT."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "description": "Full periodic-task record (the same shape GET returns). Send back the fields you read; the server re-derives `id`/`task`/`schedule_id`/`crontab.id`.",
                       "properties": {
                           "name": {"type": "string"},
                           "task": {"type": "string", "description": "Server-filled task name (`workflow.tasks.periodic_task`)."},
                           "enabled": {"type": "boolean", "description": "Cron-scheduler enable flag. Toggle this to pause/resume (does not affect manual `trigger-now`)."},
                           "crontab": {"type": "object", "properties": {
                               "minute": {"type": "string"}, "hour": {"type": "string"},
                               "day_of_week": {"type": "string"}, "day_of_month": {"type": "string"},
                               "month_of_year": {"type": "string"}, "timezone": {"type": "string"},
                           }},
                           "kwargs": {"type": "object", "properties": {
                               "wf_iri": {"type": "string"}, "exit_if_running": {"type": "boolean"},
                               "timezone": {"type": "string"}, "utcOffset": {"type": "string"},
                           }},
                           "schedule_id": {"type": "integer"},
                           "expires": {"type": "string", "nullable": True},
                           "start_time": {"type": "string", "nullable": True},
                       }},
        }}},
        "responses": {"200": _resp("The updated periodic-task record.")},
    },
    "delete": {
        "tags": ["Scheduled tasks"],
        "summary": "Delete a periodic task",
        "description": (
            "Removes the schedule entirely. To merely pause it (keep the row but "
            "stop it firing), PUT the record back with `enabled: false` instead. "
            "Returns 204 on success."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "responses": {"204": _resp("Deleted.")},
    },
}

PATHS["/api/wf/api/scheduled/trigger-now/"] = {
    "post": {
        "tags": ["Scheduled tasks"],
        "summary": "Force-trigger a periodic task now",
        "description": (
            "Fires the task immediately, out-of-band of its cron. The fire is "
            "asynchronous - the response confirms the trigger was accepted; "
            "track the resulting run via "
            "`GET /api/wf/api/workflows/?task_id=<task_id>&parent_wf__isnull=True`. "
            "Fires regardless of the task's `enabled` flag (`enabled` governs the "
            "cron scheduler, not manual triggers). The `id` is a per-request "
            "Fernet token - prefer re-resolving by `name` (a fresh GET) over "
            "holding a stale `id` from an earlier call."
        ),
        "parameters": [{"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}}],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["id"],
                       "properties": {"id": {"type": "string", "description": "Fernet token from a fresh GET /api/wf/api/scheduled/ or from the POST that created the task."}}},
        }}},
        "responses": {"200": _resp("Trigger accepted.")},
    },
}

PATHS["/api/triggers/1/{name}"] = {
    "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "User-defined endpoint name from a Custom API Endpoint trigger."}],
    "post": {
        "tags": ["Run a playbook"],
        "summary": "Run a playbook by its API endpoint name",
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
    "post": {"tags": ["Run a playbook"], "summary": "Run a playbook by its API endpoint name, asynchronously",
             "description": (
                 "Documented in the API guide as the same trigger run on a worker (202). On 8.0.0 it 404s before "
                 "authentication even for a real endpoint name (`No active workflow matching the given route.`), "
                 "while `POST /api/triggers/1/{name}` answers the same name - use that route."
             ),
             "deprecated": True,
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {},
             }}},
             "responses": {"404": _resp("Not routed on 8.0.0 - use `POST /api/triggers/1/{name}`.")}},
}

PATHS["/api/triggers/1/notrigger/{workflowId}"] = {
    "parameters": [{"name": "workflowId", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "post": {"tags": ["Run a playbook"], "summary": "Run a playbook by UUID (skips trigger conditions)",
             "description": "Runs any playbook by its workflow UUID, whatever its trigger type, without evaluating the trigger's conditions. The simplest way to run a playbook from a script.\n\nResponse carries a top-level `task_id`; track via `GET /api/wf/api/workflows/?task_id=<task_id>&parent_wf__isnull=True`.",
             "requestBody": {"required": False, "content": {"application/json": {
                 "schema": {"type": "object", "description": "Arbitrary input payload exposed to the workflow."},
                 "example": {"input": {}, "request": {"data": {}}, "useMockOutput": False, "globalMock": False},
             }}},
             "responses": {"200": _resp("Run result.", example={"task_id": "04495f62-3cc1-4067-955e-18a452a4783c"})}},
}

PATHS["/api/triggers/1/action/{routeUuid}"] = {
    "parameters": [{"name": "routeUuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "The trigger step's `route` uuid (`triggerStep.arguments.route` on the playbook), not the playbook uuid."}],
    "post": {"tags": ["Run a playbook"], "summary": "Run a manual (record action) playbook",
             "description": (
                 "What the UI's record action button calls, for playbooks whose trigger is a record action. "
                 "Extra top-level keys in the body reach the playbook as input.\n\n"
                 "Answers `{\"task_ids\": [...]}` (plural, a list), unlike the `notrigger` route's scalar `task_id`; "
                 "track each via `GET /api/wf/api/workflows/?task_id=<task_id>&parent_wf__isnull=True`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "properties": {
                     "records": {"type": "array", "items": {"type": "string"}, "description": "Record IRIs, e.g. `/api/3/alerts/<uuid>`."},
                     "__resource": {"type": "string", "description": "Module the records belong to, e.g. `alerts`."},
                     "singleRecordExecution": {"type": "boolean"},
                     "__uuid": {"type": "string", "description": "The playbook uuid. Some versions require it."},
                 }},
                 "example": {"singleRecordExecution": True, "__resource": "alerts", "records": [f"/api/3/alerts/{_UUID}"]},
             }}},
             "responses": {"200": _resp("Run accepted.", example={"task_ids": ["c0afba58-9dbe-44dd-a6e6-7227e33990dd"]})}},
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
                 "Required body fields: `name`, `connector` (integer connector id - not the name), `config` "
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

# Step 3.5: discover operations + configurations for an installed connector.
# Placed before /execute/ so the lifecycle reads install -> list ops -> execute.
# The DELETE verb on this path uninstalls; both verbs share the path object.
PATHS["/api/integration/connectors/{id}/"] = {
    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    "description": "Integer connector id (`data[].id` from `/api/integration/connectors/`)."}],
    "post": {"tags": ["Connectors"],
             "summary": "List connector operations (and configurations)",
             "description": (
                 "**This is the operations-discovery endpoint** - the only way to enumerate "
                 "the operations installed for a connector. There is no separate "
                 "`/operations/` route; this POST handler returns the full connector record, "
                 "including:\n\n"
                 "- `operations[]` - each with `operation` key, `title`, `description`, "
                 "  `parameters[]` (with `name`, `type`, `required`, `tooltip`, ...), `output_schema`.\n"
                 "- `configuration[]` - each with `config_id`, `name`, `config`, `agent`.\n"
                 "- `config_schema` - the connector's installable config field definitions.\n\n"
                 "Use the response to build a call to `POST /api/integration/execute/`:\n"
                 "- `operations[].operation` -> the `operation` body field.\n"
                 "- `operations[].parameters[]` entries with `required: true` -> the required "
                 "  keys under `params`.\n"
                 "- `configuration[].config_id` or `configuration[].name` -> the `config` field "
                 "  (both forms are accepted).\n\n"
                 "**Quirks:** GET returns `Get method for this API is forbidden, Please use POST method`. "
                 "An empty/missing body returns 415 `Unsupported media type`; send `{}` instead. "
                 "Trailing slash is required. The DELETE verb on this same path uninstalls the "
                 "connector - don't confuse the two."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object"}, "example": {}}}},
             "responses": {"200": _resp("Connector detail with operations and configurations.")}},
    "delete": {"tags": ["Connectors"], "summary": "Uninstall a connector",
               "description": "Trailing slash is required. Returns 204 on success.",
               "responses": {"204": {"description": "Uninstalled."}}},
}

# Step 4: execute a connector action.
PATHS["/api/integration/execute/"] = {
    "post": {
        "tags": ["Connectors"],
        "summary": "Execute a connector action",
        "description": (
            "Runs a connector operation against a configured connector.\n\n"
            "**Discovering what to send:** the `operation` key, its required `params`, and the "
            "available `config` values all come from `POST /api/integration/connectors/{id}/` "
            "(operations + configurations for the installed connector). There is no separate "
            "`/operations/` route - that POST is the operations-discovery endpoint.\n\n"
            "**Body fields:**\n"
            "- `connector` (required) - connector `name` (e.g. `hello-world`).\n"
            "- `operation` (required) - operation key from the connector's `info.json` "
            "  (e.g. `reverse_text`). Discover available operations via "
            "  `POST /api/integration/connectors/{id}/` (response `operations[].operation`).\n"
            "- `config` (required when the operation needs a configuration) - accepts **either** "
            "  the configuration uuid (`config_id`) **or** the configuration `name`. "
            "  Stateless operations (e.g. `cyops_utilities` formatters) still accept the field "
            "  but ignore its value. Omitting or `null` returns `INTEGRATION-12: Could not find a connector "
            "  configuration matching the given configuration id or name`.\n"
            "- `version` (optional) - connector version. If omitted, the appliance resolves the "
            "  installed default version. Provide it explicitly when multiple versions are installed.\n"
            "- `params` (required when the operation declares required parameters) - the action's "
            "  input payload as defined by the connector's `info.json`. Discover required params via "
            "  the same connector-detail endpoint (`operations[].parameters[]` with `required: true`).\n\n"
            "Errors surface as 400 with an `INTEGRATION-*` or `CS-INTEGRATION-*` code in `message`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {
                "type": "object",
                "required": ["connector", "operation"],
                "properties": {
                    "connector": {"type": "string",
                                  "description": "Connector name (e.g. `hello-world`)."},
                    "operation": {"type": "string",
                                  "description": "Operation key from the connector's `info.json` (e.g. `reverse_text`)."},
                    "config": {"type": "string",
                               "description": "Configuration uuid (`config_id`) **or** configuration `name`. Required when the operation needs a configuration."},
                    "version": {"type": "string",
                                "description": "Connector version (e.g. `1.0.4`). Optional - server resolves a default when omitted."},
                    "params": {"type": "object",
                               "description": "Action input payload. Shape varies per operation; see `operations[].parameters` from the connector detail."},
                },
            },
        }}},
        "responses": {"200": _resp("Action result.")},
    },
}

# Step 5a: healthcheck - GET form using an existing config (cheap).
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

# Step 5b: POST /api/integration/connectors/healthcheck/ was previously
# documented as an "inline body" form, but every body shape probed on
# FSR 7.6.x returned 404. The GET form above is the only working variant
# and has been retained.

# Step 6a: delete / get / update the configuration.
PATHS["/api/integration/configuration/{config_id}/"] = {
    "parameters": [{"name": "config_id", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "Configuration uuid (the `config_id` field, not the integer `id`)."}],
    "get": {"tags": ["Connectors"], "summary": "Get a connector configuration",
            "description": (
                "Fetch a single configuration record by its uuid (`config_id`). "
                "Trailing slash is mandatory (same HMAC trap as DELETE). "
                "pyfsr: `client.connectors.set_default_configuration(connector, config_id)` "
                "calls this internally to read the current config before updating."
            ),
            "responses": {"200": _resp("Configuration record."), "404": {"description": "Not found."}}},
    "put": {"tags": ["Connectors"], "summary": "Update a connector configuration",
             "description": (
                 "Replace a configuration's fields. The body is the full configuration object "
                 "(same shape as `POST /api/integration/configuration/`). To change only the "
                 "default flag, send the full body with the updated `default` field - there is "
                 "no flag-only route. Trailing slash is mandatory. "
                 "pyfsr: `client.connectors.update_configuration(connector, config_id, config, name=...)`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "properties": {
                     "name": {"type": "string"},
                     "config": {"type": "object"},
                     "default": {"type": "boolean"},
                     "status": {"type": "integer"},
                     "teams": {"type": "array", "items": {"type": "string"}},
                 }},
             }}},
             "responses": {"201": _resp("Updated configuration."), "404": {"description": "Not found."}}},
    "delete": {"tags": ["Connectors"], "summary": "Delete a connector configuration",
                "description": (
                    "**Two non-obvious requirements:** the path param must be the uuid (`config_id`), not "
                    "the integer DB id (which returns 500), and the **trailing slash is mandatory** - "
                    "without it the request is routed to an HMAC-gated handler that returns the misleading "
                    "`403 Could not validate HMAC fingerprint`."
                ),
                "responses": {"204": {"description": "Deleted."}}},
}

# Step 6b: uninstall the connector. POST returns connector detail + operations.
# DELETE for /api/integration/connectors/{id}/ is registered in the
# operations-discovery block above (placed before /execute/ in the spec
# so the discovery endpoint reads first in the lifecycle).

# --- Connector development workspace ---------------------------------------
#
# Separate flow from the install/import lifecycle above. The development
# workspace is the Connector Studio / IDE-plugin editor surface, backed by
# its own on-disk tree at `/opt/cyops/configs/integrations/connectors_development/`
# (versioned dirs suffixed with `_dev`, e.g. `armis_1_1_0_dev/`). Entities
# in this tree have integer ids in `connectors_connector` with
# `development=true`. Crucially, the Publish endpoint below is the ONLY
# connector-handling code path that calls
# `connector_development.utils.touch_dev_config_ini()`, which updates
# `/opt/cyops/configs/integrations/workspace/connector_dev_config.ini` and
# triggers uwsgi `touch-reload` -> all 10 integrations workers recycle.
# The standard install/import path (`/api/3/solutionpacks/install?$type=connector`)
# does **not** fire that signal; that asymmetry is what produces the
# "ghost version" symptom on same-version replace uploads. See
# `fortisoar/FORTISOAR_ARCHITECTURE.md` Connector upload + install pipeline
# section for the full reproduction.

PATHS["/api/integration/connector/development/entity/{id}/"] = {
    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    "description": "Integer connector id of a dev-workspace entity."}],
    "post": {
        "tags": ["Connectors"],
        "summary": "Enter edit mode on a dev-workspace connector",
        "description": (
            "Used by Connector Studio when the user clicks Edit. Pass the **installed** "
            "connector's integer id with `{\"edit_repo_connector\": true}`: the server clones it "
            "into the dev workspace and returns the twin (a new integer `id`, `development: true`) "
            "with its operations, configuration schema and file tree. Use the twin's id with the "
            "`/files/` endpoints, then `/publish/`. There is no list route: "
            "`GET .../development/entity/` answers 405 on 8.0.0 and 8.0.1."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "edit_repo_connector": {"type": "boolean", "default": True},
            }},
            "example": {"edit_repo_connector": True},
        }}},
        "responses": {"200": _resp("Editable connector detail (operations, configuration, tree).")},
    },
}

PATHS["/api/integration/connector/development/entity/{id}/files/"] = {
    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    "description": "Dev-workspace entity id."}],
    "post": {
        "tags": ["Connectors"],
        "summary": "Read a file from a dev-workspace connector",
        "description": (
            "Returns the contents of a single file inside the entity's source tree. The `xpath` "
            "is relative to the connector's dev-workspace root and always starts with "
            "`/<name>_<vtag>_dev/...`. Used by the Studio editor when the user opens a file."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["xpath"], "properties": {
                "xpath": {"type": "string",
                          "description": "Path inside the connector's dev tree, e.g. `/armis_dev_1_1_0_dev/info.json`."},
            }},
            "example": {"xpath": "/armis_dev_1_1_0_dev/info.json"},
        }}},
        "responses": {"200": _resp("`{fileContent: <string>}` with the literal file body.")},
    },
    "put": {
        "tags": ["Connectors"],
        "summary": "Write a file in a dev-workspace connector",
        "description": (
            "Replaces the contents of a single file inside the entity's source tree. Used by the "
            "Studio editor's Save action. Saved changes are staged in the workspace and do not "
            "affect playbook execution until `/publish/` is called."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["fileData"], "properties": {
                "fileData": {"type": "object", "required": ["xpath", "fileContent"], "properties": {
                    "xpath": {"type": "string"},
                    "fileContent": {"type": "string"},
                }},
            }},
            "example": {"fileData": {"xpath": "/armis_dev_1_1_0_dev/operations.py",
                                     "fileContent": "# ... full file body ..."}},
        }}},
        "responses": {"200": _resp("Updated tree view of the entity (folders + files).")},
    },
}

PATHS["/api/integration/connector/development/entity/{id}/publish/"] = {
    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"},
                    "description": "Dev-workspace entity id."}],
    "post": {
        "tags": ["Connectors"],
        "summary": "Publish a dev-workspace connector to the running appliance",
        "description": (
            "Lands the dev-workspace contents into the live installed-connectors area and signals "
            "the integrations service to refresh, so subsequent playbook executions pick up the new "
            "code immediately. This is the recommended way to land changes made via the Studio "
            "editor, and it is the supported escape hatch when a same-version tgz upload has left "
            "stale code cached in the integrations service (publish triggers a service refresh "
            "that the standard `$replace=true` install path does not). `replace=true` overwrites an existing "
            "installed version of the same name + version. `discard` controls the dev-workspace "
            "twin's lifecycle, NOT whether edits are published - see the field description. "
            "The published connector gets a **new integer id**; look it up again by name "
            "afterwards. Publishing also recycles the integrations workers, so "
            "`/api/integration/*` can answer 502 for a few seconds."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "discard": {"type": "boolean", "default": False,
                            "description": "Controls the dev-workspace twin after a successful "
                                           "publish, scoped to THIS connector only - other "
                                           "connectors' dev workspaces are untouched. `true` "
                                           "destroys this connector's dev twin (one-shot "
                                           "publish), `false` keeps it (`development=true` row "
                                           "remains for further editing). Both values publish the "
                                           "staged edits to the installed connector dir - the "
                                           "flag does NOT mean 'don't publish'."},
                "replace": {"type": "boolean", "default": False,
                            "description": "If true, overwrite an existing same-name+version install."},
            }},
            "example": {"discard": False, "replace": True},
        }}},
        "responses": {"200": _resp("Published connector record (with integer `id`, configurations, operations).")},
    },
}

# --- Connector lifecycle on a remote agent ---------------------------------
#
# These three routes target connectors that live on a **remote agent** rather
# than the appliance's self-agent. They sit alongside `/api/integration/*` and
# are tagged Connectors so they group with the rest of the lifecycle.

PATHS["/api/integration/install-connector/"] = {
    "post": {"tags": ["Connectors"],
             "summary": "Install a connector on an agent",
             "description": (
                 "Installs (or re-installs) a connector on a specific remote agent. The "
                 "appliance proxies the install to the named agent over SME; the response is "
                 "the same envelope shape as the rest of `/api/integration/*` (`status`, "
                 "`data`).\n\n"
                 "**Body fields:**\n"
                 "- `name` (required) - connector name (e.g. `hello-world`).\n"
                 "- `version` (required) - connector version (e.g. `1.0.4`).\n"
                 "- `agent_id` (required for remote install) - the agent's hash identifier "
                 "  (the `agent` value from `GET /api/integration/configuration/?agent=...`, "
                 "  not the agent record uuid). Omit to target the self-agent.\n\n"
                 "Use `PUT` on the same path to upgrade an installed connector to a different "
                 "version, and `DELETE` to uninstall it from the agent.\n\n"
                 "**Also needs the connector's rpm name.** With only `name`/`version`/`agent_id`, "
                 "8.0.0 answers 400 `Invalid Input :: No connector rpm name or rpm_full_name was "
                 "provided` (DELETE: `No connector rpm name was provided`). Connectors installed "
                 "from content-hub bundles report an empty `rpm_full_name`. No 2xx body has been "
                 "captured for these three operations."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "required": ["name", "version"], "properties": {
                     "name": {"type": "string"},
                     "version": {"type": "string"},
                     "agent_id": {"type": "string",
                                  "description": "Agent hash identifier. Omit to install on the appliance's self-agent."},
                 }},
             }}},
             "responses": {"200": _resp("Install accepted.")}},
    "put": {"tags": ["Connectors"],
            "summary": "Upgrade a connector on an agent",
            "description": (
                "Upgrades an installed connector on a remote agent to the version supplied in "
                "the body. Same body shape as `POST`."
            ),
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "required": ["name", "version"], "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "agent_id": {"type": "string"},
                }},
            }}},
            "responses": {"200": _resp("Upgrade accepted.")}},
    "delete": {"tags": ["Connectors"],
               "summary": "Uninstall a connector from an agent",
               "description": (
                   "Uninstalls the named connector from the supplied agent. Distinct from "
                   "`DELETE /api/integration/connectors/{id}/`, which uninstalls from the "
                   "appliance's self-agent by integer id."
               ),
               "requestBody": {"required": True, "content": {"application/json": {
                   "schema": {"type": "object", "required": ["name", "version"], "properties": {
                       "name": {"type": "string"},
                       "version": {"type": "string"},
                       "agent_id": {"type": "string"},
                   }},
               }}},
               "responses": {"200": _resp("Uninstall accepted.")}},
}

PATHS["/api/integration/connectors/agents/{name}/{version}/"] = {
    "parameters": [
        {"name": "name", "in": "path", "required": True,
         "schema": {"type": "string"},
         "description": "Connector name (e.g. `hello-world`)."},
        {"name": "version", "in": "path", "required": True,
         "schema": {"type": "string"},
         "description": "Connector version (e.g. `1.0.4`)."},
    ],
    "post": {"tags": ["Connectors"],
            "summary": "List agents that have this connector installed",
            "parameters": [
                {"name": "format", "in": "query", "schema": {"type": "string", "default": "json"}},
                {"name": "active", "in": "query", "schema": {"type": "boolean"},
                 "description": "Only active agents."},
            ],
            "requestBody": {"required": False, "content": {"application/json": {
                "schema": {"type": "object"}, "example": {}}}},
            "description": (
                "**POST**, with an empty body: a `GET` answers 405 `Method \"GET\" not allowed`. "
                "Returns the set of agents on which the named `{name}/{version}` connector is "
                "installed, alongside per-agent install status. Use this to discover which "
                "remote agents already have a given connector before issuing "
                "`POST /api/integration/install-connector/` or "
                "`POST /api/integration/configuration/` with an `agent` value."
            ),
            "responses": {"200": _resp("Per-agent install records.")}},
}

PATHS["/api/integration/agent-heartbeat/{agent}/"] = {
    "parameters": [
        {"name": "agent", "in": "path", "required": True,
         "schema": {"type": "string"},
         "description": (
             "Agent hash identifier (the `agent` field returned in `GET /api/integration/configuration/`, "
             "not the agent record uuid)."
         )},
    ],
    "get": {"tags": ["Connectors"],
            "summary": "Agent heartbeat probe",
            "description": (
                "Round-trips a heartbeat message to the named remote agent over SME and "
                "returns its liveness response. Independent of the agent record's "
                "`configurationHealth.itemValue` field, which is updated asynchronously: this "
                "probe surfaces the current state of the SME bus to the agent."
            ),
            "responses": {"200": _resp("Heartbeat reply.")}},
}


# --- Connector internals (pyfsr-discovered) --------------------------------
#
# These endpoints are not in the API guide but pyfsr wraps them. They cover
# connector definition fetching, dependency checking, output schema lookup,
# ingestion metadata, and ingestion source listing.

PATHS["/api/integration/connectors/{connector}/{version}/"] = {
    "parameters": [
        {"name": "connector", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector name (e.g. `mitre-attack`)."},
        {"name": "version", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector version (e.g. `1.0.0`)."},
    ],
    "post": {"tags": ["Connectors"],
             "summary": "Fetch a connector's full definition (config schema + operations)",
             "description": (
                 "Returns the connector's complete definition including `config_schema`, "
                 "`configuration`, and typed `operations` (each with `operation`, `title`, "
                 "`parameters`, `output_schema`). GET is forbidden on this endpoint - "
                 "use POST with `?format=json`. pyfsr: "
                 "`client.connectors.definition(connector, version)`."
             ),
             "parameters": [
                {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json"]},
                 "description": "Must be `json`."},
             ],
             "requestBody": {"required": False, "content": {"application/json": {"schema": {"type": "object"}}}},
             "responses": {"200": _resp("Connector definition with operations and config schema.")}},
}

PATHS["/api/integration/connectors/dependencies_check/{connector}/{version}/"] = {
    "parameters": [
        {"name": "connector", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector name."},
        {"name": "version", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector version."},
    ],
    "get": {"tags": ["Connectors"],
            "summary": "Check if connector Python dependencies are installed",
            "description": (
                "Returns the dependency-install status for the connector - whether the "
                "Python packages the connector needs are present on the appliance (or a "
                "named remote agent). The response includes `dependencies_installed` "
                "(bool). pyfsr: `client.connectors.dependencies_status(connector, version)`."
            ),
            "parameters": [
                {"name": "agent", "in": "query", "schema": {"type": "string"},
                 "description": "Remote agent identifier. Omit for the self-agent."},
            ],
            "responses": {"200": _resp("Dependency status.")}},
    "post": {"tags": ["Connectors"],
             "summary": "Retry connector dependency installation",
             "description": (
                 "Triggers a retry of the Python-dependency install for a connector - "
                 "the Retry button next to a failed Requirements badge. Pass `agent` to "
                 "install dependencies on a remote agent instead of the appliance. "
                 "pyfsr: `client.connectors.install_dependencies(connector, version)`."
             ),
             "parameters": [
                {"name": "agent", "in": "query", "schema": {"type": "string"},
                 "description": "Remote agent identifier. Omit for the self-agent."},
             ],
             "responses": {"200": _resp("Install retry accepted.")}},
}

PATHS["/api/integration/connector_output_schema/{connector}/{version}/"] = {
    "parameters": [
        {"name": "connector", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector name."},
        {"name": "version", "in": "path", "required": True, "schema": {"type": "string"},
         "description": "Connector version."},
    ],
    "post": {"tags": ["Connectors"],
             "summary": "Get a connector operation's output schema",
             "description": (
                 "Returns the output schema for a connector operation - the shape of "
                 "the data the operation returns. pyfsr: "
                 "`client.connectors.output_schema(connector, version, operation)`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "properties": {
                     "operation": {"type": "string", "description": "Operation key."},
                 }},
             }}},
             "responses": {"200": _resp("Output schema for the operation.")}},
}

PATHS["/api/integration/connector_details/"] = {
    "post": {"tags": ["Connectors"],
             "summary": "List ingestion sources for a connector",
             "description": (
                 "Returns the ingestion source configurations (data sources) for a "
                 "connector - the entries visible in the connector's Data Source tab. "
                 "pyfsr: `client.connectors.ingestion_sources(connector)`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "properties": {
                     "connector": {"type": "string", "description": "Connector name."},
                 }},
             }}},
             "responses": {"200": _resp("Ingestion sources.")}},
}

PATHS["/api/integration/data-import/"] = {
    "get": {"tags": ["Connectors"],
            "summary": "List ingestion metadata records",
            "description": (
                "Returns the metadata records for data-import jobs - the ingestion "
                "tracking entries created by connector data-source configurations. "
                "pyfsr: `client.connectors.ingestion_metadata()`."
            ),
            "responses": {"200": _resp("Array of ingestion metadata records.")}},
    "post": {"tags": ["Connectors"],
             "summary": "Save ingestion metadata",
             "description": (
                 "Create an ingestion metadata record. Returns 201 with the record. pyfsr: "
                 "`client.connectors.save_ingestion_metadata(config_id, connector=..., version=..., name=...)`."
             ),
             "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
             "responses": {"201": _resp("Saved metadata record.")}},
}


# --- Agents / SME router ---------------------------------------------------
#
# Agent records are exposed through the generic `/api/3/{collection}` template,
# but creation returns a one-shot payload (encryption key, rabbit password,
# vhost, username) that the installer needs and that no other module returns.
# Documenting agents explicitly keeps that contract visible.

_AGENT_CREATE_PROPS = {
    "name": {"type": "string",
             "description": "Display name shown in the FortiSOAR UI."},
    "router": {"type": "string",
               "description": "IRI of the SME router (`@id` from `GET /api/3/routers`)."},
    "installerType": {"type": "string",
                      "description": (
                          "Picklist IRI selecting the installer flavour. The two values are stable across "
                          "installs: `/api/3/picklists/a8181039-30a0-4807-b470-50de69d37561` (bash) and "
                          "`/api/3/picklists/d9f874be-3068-4282-9aed-100eba51e61b` (docker)."
                      )},
    "description": {"type": "string",
                    "description": "Free-text. Useful for tagging records owned by automation."},
}

PATHS["/api/3/agents"] = {
    "get": {"tags": ["Agents"], "summary": "List agents",
            "description": (
                "Hydra collection of agent records. The appliance's **Self agent** is included with "
                "`role: self` and is hardcoded at uuid `973c17df-bb4b-41e5-b59c-a408666fdf27` on every "
                "install; its `agentId` (the runtime `masterId` used in agent config) varies per "
                "appliance and must be read from the response. Health is reported under "
                "`configurationHealth.itemValue` - typical values are `Awaiting Remote Node Connection`, "
                "`Remote Node Connected`, `Remote Node Unreachable`, and `Configuration In Progress`."
            ),
            "responses": {"200": _resp("Hydra collection of Agent.")}},
    "post": {"tags": ["Agents"], "summary": "Create an agent record",
             "description": (
                 "Creates a remote-agent record on the FortiSOAR master and returns the one-shot "
                 "credentials the installer needs.\n\n"
                 "**Response carries (alongside the usual `uuid`, `@id`, `agentId`):**\n"
                 "- `encryptionKey` - the peerwise key the installer bakes into the agent VM's keystore.\n"
                 "- `username`, `password`, `vhost` - the messaging credentials the agent uses to dial SME.\n\n"
                 "These secrets are returned **only once**; if the response is lost the record must be "
                 "deleted and re-created. The newly-created record starts in `Awaiting Remote Node "
                 "Connection`; it transitions to `Remote Node Connected` after the installer runs on "
                 "the target VM.\n\n"
                 "**Prerequisite:** the appliance must have an SME router configured "
                 "(`GET /api/3/routers` non-empty). If it doesn't, run "
                 "`sudo csadm secure-message-exchange enable` on the master first."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object",
                            "required": ["name", "router", "installerType"],
                            "properties": _AGENT_CREATE_PROPS},
             }}},
             "responses": {"201": _resp(
                 "Agent record with one-shot installer credentials "
                 "(`encryptionKey`, `username`, `password`, `vhost`).")}},
}

PATHS["/api/3/agents/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True,
                    "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Agents"], "summary": "Get an agent record",
            "description": (
                "Returns the full agent record including `agentId`, `role`, `configurationHealth`, and "
                "`router`. Polling this endpoint is how callers wait for `configurationHealth.itemValue` "
                "to reach `Remote Node Connected` after running the installer.\n\n"
                "**Self-agent lookup:** `GET /api/3/agents/973c17df-bb4b-41e5-b59c-a408666fdf27` returns "
                "this appliance's Self agent on every install - use it to learn the appliance's "
                "`agentId` (the runtime `masterId`)."
            ),
            "responses": {"200": _resp("Agent record.")}},
    "delete": {"tags": ["Agents"], "summary": "Delete an agent record",
               "description": (
                   "Returns 204. Deleting the FSR-side record does **not** uninstall the agent on the "
                   "remote VM - that requires SSH-level cleanup. After delete the record's `agentId` is "
                   "released and a fresh `POST /api/3/agents` will mint a new one."
               ),
               "responses": {"204": {"description": "Deleted."}}},
}

PATHS["/api/3/routers"] = {
    "get": {"tags": ["Agents"], "summary": "List SME routers",
            "description": (
                "Hydra collection of Secure Message Exchange (SME) router records. The "
                "agent-creation flow reads the first member to populate the `router` IRI on "
                "`POST /api/3/agents`. Per-item fields of interest:\n\n"
                "- `@id` - the IRI passed as `router` when creating an agent.\n"
                "- `address` - hostname the agent dials; **must match the router's TLS cert CN** "
                "  (the agent VM typically needs an `/etc/hosts` entry mapping this to the appliance IP).\n"
                "- `sni` - SNI value used in the TLS handshake (usually equals `address`).\n"
                "- `certificate` - server CA in PEM, written to the agent VM as `ca_cert.pem`.\n\n"
                "**Empty collection means SME isn't enabled.** Run "
                "`sudo csadm secure-message-exchange enable` on the master before creating agents."
            ),
            "responses": {"200": _resp("Hydra collection of Router.")}},
}

PATHS["/api/integration/agent-installer/"] = {
    "post": {"tags": ["Agents"], "summary": "Download the agent installer",
             "description": (
                 "Returns the per-agent installer binary (bash `.bin` or docker bundle, depending on "
                 "the agent record's `installerType`).\n\n"
                 "**Body fields:**\n"
                 "- `agent` (required) - the `agentId` (not the uuid) returned by `POST /api/3/agents`.\n"
                 "- `connectors` (optional) - list of connector IRIs to pre-bundle. Empty = base installer.\n"
                 "- `include_last_known_configurations` (optional, boolean) - bake existing connector "
                 "  configurations into the installer. Defaults to `false`.\n\n"
                 "**Response is binary**, served as `application/octet-stream` (the `?format=json` query "
                 "parameter only changes the envelope of error responses, not success). Successful "
                 "payloads are several megabytes; anything under ~1 KB indicates a server-side error "
                 "that returned HTTP 200 with a JSON error body.\n\n"
                 "The bash installer ships with an unset `s_user_input=\"\"` placeholder near the top; "
                 "automated installs patch that line with the agent's `encryptionKey` before running."
             ),
             "parameters": [
                 {"name": "format", "in": "query", "required": False,
                  "schema": {"type": "string", "enum": ["json"]},
                  "description": "Forces JSON error envelopes; has no effect on the binary success body."},
             ],
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "required": ["agent"], "properties": {
                     "agent": {"type": "string",
                               "description": "Agent `agentId` (from `POST /api/3/agents` response)."},
                     "connectors": {"type": "array", "items": {"type": "string"},
                                    "description": "Optional connector IRIs to pre-bundle."},
                     "include_last_known_configurations": {"type": "boolean", "default": False},
                 }},
             }}},
             "responses": {"200": {
                 "description": "Installer binary.",
                 "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}}},
}


# --- Modules ---------------------------------------------------------------
# Module + field schema: discovery (model_metadatas / staging_model_metadatas)
# and the module editor (staging CRUD + appliance-wide publish). The two-store
# model (staging draft -> publish -> live) and the storage-vs-display field-type
# distinction are documented in the "Modules" section of the introduction.

# Filter params for the two metadata COLLECTION endpoints. Same role as
# RECORD_FILTER_QPARAMS: illustrative, not exhaustive - the URL-param grammar
# accepts any column on ModelMetadata with any operator. Every entry below was
# live-verified against 8.0.0 on both /api/3/model_metadatas and
# /api/3/staging_model_metadatas (identical behaviour on each).
MODULE_METADATA_FILTER_QPARAMS = [
    {"name": "type", "in": "query",
     "description": (
         "Exact-match filter on the module slug. **This is how you fetch one module's schema "
         "without knowing its uuid** - pair it with `$relationships=true` and you get the full "
         "definition in a single request instead of listing every module to find the uuid first. "
         "Case-sensitive: `alerts` matches, `Alerts` returns 0."
     ),
     "schema": {"type": "string"}, "example": "alerts"},
    {"name": "module", "in": "query",
     "description": "Same value as `type` on every stock module; filters identically.",
     "schema": {"type": "string"}, "example": "alerts"},
    {"name": "tableName", "in": "query",
     "description": "Filter by the underlying table name (usually == `type`; differs after a table rename).",
     "schema": {"type": "string"}, "example": "alerts"},
    {"name": "type$in", "in": "query",
     "description": "Multi-module fetch, pipe-delimited - one round-trip for several schemas.",
     "schema": {"type": "string"}, "example": "alerts|incidents"},
    {"name": "type$like", "in": "query",
     "description": "Case-insensitive LIKE on the slug. Use `%` and `_` wildcards.",
     "schema": {"type": "string"}, "example": "%alert%"},
    {"name": "system", "in": "query",
     "description": "`false` returns only non-system (custom + customised) modules.",
     "schema": {"type": "boolean"}, "example": False},
    {"name": "attributes.name", "in": "query",
     "description": (
         "Dot-notation into the field list: returns every module that HAS a field with this name - "
         "the cheap answer to \"which modules define `severity`?\". Works with or without "
         "`$relationships=true`. Note it selects **modules**, not fields: each match still carries "
         "its complete `attributes` list, not just the matching field."
     ),
     "schema": {"type": "string"}, "example": "severity"},
]

# Caveats measured on these two endpoints specifically; spliced in alongside
# COMMON_QPARAMS so the generic descriptions don't mislead here.
_MM_FIELDS_CAVEAT = {
    "name": "$fields", "in": "query",
    "description": (
        "Comma-separated projection. **Cannot be combined with `$relationships=true` on this "
        "endpoint** - the pair returns `500 Internal Server Error` (not a 400). Use one or the "
        "other: `$fields` for a cheap module inventory, `$relationships` for full schemas."
    ),
    "schema": {"type": "string"}, "example": "type,uuid"}
_MM_SEARCH_CAVEAT = {
    "name": "$search", "in": "query",
    "description": (
        "Accepted but always returns 0 matches here - ModelMetadata declares no searchable "
        "fields. Filter on `type` / `type$like` instead."
    ),
    "schema": {"type": "string"}}
MODULE_METADATA_QPARAMS = [
    p for p in COMMON_QPARAMS if p["name"] not in ("$fields", "$search")
] + [_MM_FIELDS_CAVEAT, _MM_SEARCH_CAVEAT] + MODULE_METADATA_FILTER_QPARAMS

# Shared tail for both collection descriptions - the one-request recipe plus the
# numbers that justify it (measured on 8.0.0, alerts module, 126 attributes).
_MM_ONE_SHOT = (
    "\n\n**One module in one request:** `?type=<slug>&$relationships=true`. The `type` filter "
    "alone returns the module's header row with an **empty** `attributes` list (~1.6 KB); adding "
    "`$relationships=true` populates all fields (~227 KB for `alerts`). The result is identical "
    "to the by-uuid GET apart from an added `@context`, so there is no reason to list every "
    "module and then fetch by uuid."
)

PATHS["/api/3/model_metadatas"] = {
    "get": {"tags": ["Modules"], "summary": "List published module definitions",
            "description": (
                "The published schema - every module with its committed fields. This is the "
                "drift-resistant source of truth for what a module actually looks like on this "
                "appliance (versus a static schema snapshot). Each entry's `@id`/`uuid` is the "
                "IRI you pass to `/api/query` `models`, and `attributes` is the field list. Add "
                "`?$relationships=true` to populate `attributes` (omitted by default)."
                + _MM_ONE_SHOT
            ),
            "parameters": MODULE_METADATA_QPARAMS,
            "responses": {"200": _resp("Hydra collection of ModelMetadata records.")}},
}

PATHS["/api/3/model_metadatas/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Modules"], "summary": "Published module definition",
            "description": (
                "One committed module schema record by uuid, with its `attributes` (fields). "
                "Add `?$relationships=true` to fully populate each attribute's `dataSource` "
                "(picklist binding) and relationship metadata. The published store is what "
                "record reads are validated against; a module that exists only in staging "
                "is not yet live."
                "\n\nIf you have the module slug but not its uuid, prefer "
                "`GET /api/3/model_metadatas?type=<slug>&$relationships=true` - same payload, "
                "no uuid lookup first."
            ),
            "responses": {"200": _resp("A ModelMetadata record.")}},
}

PATHS["/api/3/staging_model_metadatas"] = {
    "get": {"tags": ["Modules"], "summary": "List staged module definitions (drafts)",
            "description": (
                "The editable draft schema. The in-product Module Editor and any staging write "
                "target this store; nothing here is live until `PUT /api/publish`. On many "
                "appliances staging mirrors published, so the two lists match when the "
                "appliance is fully published. Add `?$relationships=true` to populate "
                "`attributes` (required to diff staged vs. published for field-level changes)."
                + _MM_ONE_SHOT
            ),
            "parameters": MODULE_METADATA_QPARAMS,
            "responses": {"200": _resp("Hydra collection of staging ModelMetadata records.")}},
    "post": {
        "tags": ["Modules"],
        "summary": "Create a module (staged)",
        "description": (
            "Stages a new module. Nothing is live until `PUT /api/publish` commits it. "
            "`type`/`module`/`tableName` are the module's API slug (lowercase, "
            "`[a-z][a-z0-9_]*`); they are usually identical. `attributes` is the field list - "
            "each field needs both a storage `type` and a display `formType` (see "
            "[Modules](#description/modules)). A field whose `type` is a display type (e.g. "
            "`text`) fails the publish validator with \"Attribute type 'text' does not exist\" - "
            "store `string` for text-like fields.\n\n"
            "`?$relationships=true` is conventional on the POST so the response includes the "
            "staged `attributes`. Creating a module does **not** create its list/detail/form "
            "view layouts - post those to `/api/3/bulkupsert/system_view_templates` separately, "
            "or the module has no grid/detail render in the UI."
        ),
        "parameters": [{"name": "$relationships", "in": "query", "schema": {"type": "boolean"},
                       "description": "Populate `attributes` in the response."}],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "required": ["type", "module", "attributes"],
                       "properties": {
                           "type": {"type": "string", "description": "Module slug (also the record `@type`)."},
                           "module": {"type": "string", "description": "Collection name used in `/api/3/<module>`."},
                           "tableName": {"type": "string", "description": "Underlying table name (usually == `type`)."},
                           "displayName": {"type": "string", "description": "Display template, e.g. `{{ name }}`."},
                           "descriptions": {"type": "object",
                                            "description": "Singular/plural labels.",
                                            "properties": {"singular": {"type": "string"}, "plural": {"type": "string"}}},
                           "ownable": {"type": "boolean", "default": False},
                           "taggable": {"type": "boolean", "default": False},
                           "queueable": {"type": "boolean", "default": False},
                           "softDeleteable": {"type": "boolean", "default": False, "description": "Recycle-bin on delete."},
                           "peerReplicable": {"type": "boolean", "default": False, "description": "Multi-tenancy."},
                           "system": {"type": "boolean", "default": False},
                           "uniqueConstraint": {"type": "array", "description": "Record uniqueness, as `[{<table>_unique: {columns: [..]}}]`."},
                           "defaultSort": {"type": "array"},
                           "attributes": {"type": "array",
                                          "description": "Field list. Each field needs `name`, `type`, `formType`.",
                                          "items": {"type": "object", "properties": {
                                              "name": {"type": "string"},
                                              "type": {"type": "string", "description": "Storage type (`string`/`integer`/`float`/`boolean`/`picklists`/`object`/`array`/target module)."},
                                              "formType": {"type": "string", "description": "Display type (`text`/`textarea`/`datetime`/`picklist`/`lookup`/...)."},
                                              "descriptions": {"type": "object"},
                                              "validation": {"type": "object", "properties": {"required": {"type": ["boolean", "object"]}}},
                                          }},
                           },
                        }},
        }}},
        "responses": {"201": _resp("The staged module metadata record.")},
    },
}

PATHS["/api/3/staging_model_metadatas/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Modules"], "summary": "Staged module definition (draft)",
            "description": (
                "One staged module record by uuid, with its draft `attributes`. Add "
                "`?$relationships=true` to populate each attribute's `dataSource`."
                "\n\nIf you have the module slug but not its uuid, prefer "
                "`GET /api/3/staging_model_metadatas?type=<slug>&$relationships=true`."
            ),
            "parameters": [{"name": "$relationships", "in": "query", "schema": {"type": "boolean"}}],
            "responses": {"200": _resp("A staging ModelMetadata record.")}},
    "put": {
        "tags": ["Modules"],
        "summary": "Update a module's staged fields / settings",
        "description": (
            "Edits the staged draft. A full-record PUT is rejected - the GET payload carries "
            "read-only `@id`/`@context` keys - so PUT only the changed keys. To add or remove a "
            "field, PUT `{\"attributes\": [...]}` with the full attribute list (append or remove "
            "the entry). To change module settings, PUT the changed keys (e.g. "
            "`{\"ownable\": true, \"userOwnable\": true}`). Change is staged until "
            "`PUT /api/publish`."
        ),
        "parameters": [{"name": "$relationships", "in": "query", "schema": {"type": "boolean"}}],
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "properties": {
                           "attributes": {"type": "array", "description": "Full field list (replace).",
                                          "items": {"type": "object"}},
                           "ownable": {"type": "boolean"},
                           "taggable": {"type": "boolean"},
                           "queueable": {"type": "boolean"},
                           "softDeleteable": {"type": "boolean"},
                           "displayName": {"type": "string"},
                           "defaultSort": {"type": "array"},
                           "uniqueConstraint": {"type": "array"},
                        }},
        }}},
        "responses": {"200": _resp("The updated staging ModelMetadata record.")},
    },
    "delete": {
        "tags": ["Modules"],
        "summary": "Discard a module's staging draft",
        "description": (
            "Deletes the staged draft for a module (the in-product editor's \"Revert\" for an "
            "unpublished module). This is **not** a module delete on its own: if the module was "
            "never published it removes it; if it was published, the published record remains and "
            "on the **next** `PUT /api/publish` that record is deleted (the module disappears "
            "from the API). To delete a published module safely, remove its reverse "
            "relationships first. 204 on success."
        ),
        "responses": {"204": _resp("Draft discarded.")},
    },
}

PATHS["/api/publish"] = {
    "put": {
        "tags": ["Modules"],
        "summary": "Publish all staged schema changes (appliance-wide)",
        "description": (
            "Promotes **every** pending staged change across the whole instance to live - not "
            "just modules you touched. The PUT only *starts* the publish; the backup + migrate "
            "then runs server-side, during which some surfaces may be briefly unavailable (see "
            "[Modules -> Publish blast radius](#description/publish-blast-radius)). Poll "
            "`GET /api/publish/error` until `last_publish_time` advances and `status` reads "
            "`Success`.\n\n"
            "A no-op publish (nothing staged) returns right away with no migrate. One "
            "illegally-named draft anywhere can fail the whole migrate with a cryptic error that "
            "does not name the offender - validate drafts before publishing. Schema validation "
            "errors (e.g. a relationship with no matching reverse field) are returned "
            "synchronously on the PUT itself.\n\n"
            "Live-verified on 8.0.0 with an empty staging table: `200 {\"@type\": \"Publish\", "
            "\"status\": \"started\"}`. NOT exercise-captured on the reference appliance: its "
            "staging table permanently holds ~78 foreign staged rows, and a publish here would "
            "flush those into the live schema. The live-test runner only calls this op when the "
            "staging table is empty and skips otherwise."
        ),
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object"}, "example": {},
        }}},
        "responses": {
            "200": _resp("Publish started.", example={"status": "started"}),
            "400": _err(400, "Schema validation rejected the publish."),
        },
    },
}

PATHS["/api/publish/revert"] = {
    "put": {
        "tags": ["Modules"],
        "summary": "Discard all staged schema changes (appliance-wide)",
        "description": (
            "The inverse of `PUT /api/publish`: drops every uncommitted staged change across "
            "the whole instance so staging matches the published schema again. Use it to "
            "abandon a half-built change or clear a wedged draft. Appliance-wide - not scoped to "
            "modules you touched. Unlike publish there is no migrate, so it returns "
            "synchronously."
        ),
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object"}, "example": {},
        }}},
        "responses": {"200": _resp("Staging reverted.", example={"status": "Success"})},
    },
}

PATHS["/api/publish/error"] = {
    "get": {
        "tags": ["Modules"],
        "summary": "Last publish status / error",
        "description": (
            "Reports the outcome of the most recent `PUT /api/publish`: "
            "`{\"status\": \"Success\"|\"Failed\"|..., \"last_publish_time\": <epoch>, \"errors\": ...}`. "
            "A fresh `last_publish_time` with `status == \"Success\"` means the publish committed. "
            "**Returns HTTP 400 (not 200)** when a prior publish error is on record - the body "
            "still carries the same `status`/`last_publish_time` fields, so read it "
            "status-agnostically. Useful as the readiness probe when polling a publish to "
            "completion."
        ),
        "responses": {
            "200": _resp("Last publish status.", example={"status": "Success", "last_publish_time": 1736380800}),
            "400": _err(400, "A prior publish error is on record (body still carries status fields)."),
        },
    },
}

# --- Metadata --------------------------------------------------------------
# Picklist taxonomies + values, Hydra @context docs, and the auto-generated
# full API listing. Module definitions live under the Modules tag above.

PATHS["/api/3/picklists"] = {
    "post": {
        "tags": ["Metadata"],
        "summary": "Add an option (item) to a picklist",
        "description": (
            "Creates one picklist value (an *option*) under an existing taxonomy. "
            "`listName` is the owning list's IRI (`/api/3/picklist_names/<uuid>`). "
            "Duplicate `itemValue` within a list is allowed (no unique constraint "
            "on it). Optional `color` is a hex color; optional `orderIndex` sets "
            "the position (defaults to appending). The response carries the new "
            "item's `@id` - that IRI is what a record field stores for this value."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["itemValue", "listName"],
                       "properties": {
                           "itemValue": {"type": "string", "description": "The option's friendly label (what a record field points at by IRI)."},
                           "listName": {"type": "string", "description": "Owning picklist taxonomy IRI (`/api/3/picklist_names/<uuid>`)."},
                           "color": {"type": "string", "description": "Optional hex color (e.g. `#FF0000`)."},
                           "orderIndex": {"type": "integer", "description": "Optional position; defaults to appending after the list's current highest index."},
                       }},
        }}},
        "responses": {"201": _resp("The created picklist item record.")},
    },
}

PATHS["/api/3/picklists/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist value",
            "description": (
                "Resolves one picklist *value* record by uuid - the leaf entries that record fields point at "
                "(`severity`, `status`, etc.). The owning picklist taxonomy is `GET /api/3/picklist_names/{uuid}`."
            ),
            "responses": {"200": _resp("Picklist record.")}},
    "delete": {
        "tags": ["Metadata"],
        "summary": "Delete a picklist option (item)",
        "description": (
            "Deletes one picklist value by uuid. 204 on success. Records still "
            "pointing at the deleted item's IRI are not cleaned up - resolve "
            "references before deleting if you need a tidy state."
        ),
        "responses": {"204": _resp("Deleted.")},
    },
}

PATHS["/api/3/picklist_names"] = {
    "get": {"tags": ["Metadata"], "summary": "List picklist taxonomies",
            "description": (
                "Hydra collection of every picklist *taxonomy* (named list). Each entry's `@id` is the "
                "IRI you pass as `listName` when fetching values via "
                "`GET /api/3/picklists?listName=<iri>`. Names are PascalCase "
                "(e.g. `AlertSeverity`, `AlertStatus`, `Severity`)."
            ),
            "responses": {"200": _resp("Hydra collection of picklist taxonomies.")}},
    "post": {
        "tags": ["Metadata"],
        "summary": "Create a picklist taxonomy",
        "description": (
            "Creates a new named picklist list (a *taxonomy*). A list `name` is "
            "unique instance-wide - a duplicate returns 409 "
            "(`UniqueConstraintViolationException`). Custom lists are created "
            "with `system: false`; set `system: true` only for platform-managed "
            "lists (rare). The response carries the new `@id`/`@type`/`uuid`/"
            "`name`. Add options to the new list with `POST /api/3/picklists`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["name"],
                       "properties": {
                           "name": {"type": "string", "description": "Picklist display name (PascalCase, e.g. `AlertStatus`). Unique instance-wide."},
                           "system": {"type": "boolean", "default": False, "description": "Platform-managed flag. Custom lists are `false`."},
                       }},
        }}},
        "responses": {"201": _resp("The created picklist taxonomy record.")},
    },
}

PATHS["/api/3/picklist_names/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {"tags": ["Metadata"], "summary": "Picklist taxonomy",
            "description": (
                "Resolves one picklist *taxonomy* record by uuid - the named list (e.g. `AlertSeverity`) "
                "whose members are exposed via `GET /api/3/picklists/{uuid}`."
            ),
            "responses": {"200": _resp("Picklist name record.")}},
    "delete": {
        "tags": ["Metadata"],
        "summary": "Delete a picklist taxonomy (cascades to its items)",
        "description": (
            "Deletes one picklist taxonomy by uuid. 204 on success. **Cascade** "
            "- the list's option items are removed too. To clear the list's "
            "contents but keep the taxonomy, delete the individual items via "
            "`DELETE /api/3/picklists/{uuid}` instead."
        ),
        "responses": {"204": _resp("Deleted.")},
    },
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


# --- Widgets ---------------------------------------------------------------
# Widget publish, export, and delete. The upload path is shared with
# connectors (`POST /api/3/solutionpacks/install?$type=widget`, already
# documented under Connectors) - only these widget-specific ops are new.

PATHS["/api/3/widgets/development/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {
        "tags": ["Widgets"],
        "summary": "Read the development-workspace manifest",
        "description": (
            "Returns the development-workspace manifest for a widget (the "
            "draft, not-yet-published copy). Used by the publish step - "
            "`PUT /api/3/widgets/{uuid}` loads this, strips `tree`, adds "
            "publish flags, and PUTs it back. Hydra envelope."
        ),
        "responses": {"200": _resp("Hydra envelope with the widget development manifest.")},
    },
}

PATHS["/api/3/widgets/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "put": {
        "tags": ["Widgets"],
        "summary": "Publish a widget",
        "description": (
            "Publishes an uploaded widget from the development workspace to "
            "live. The body is the development manifest (from `GET "
            "/api/3/widgets/development/{uuid}`) with `tree` stripped, plus "
            "the publish flags: `draft` (false to go live), `installed` "
            "(true), `enablePublish` (false), `replace` + `replaceVersions` "
            "(version-supersede flags), `publishedDate`, and `@id`. This is "
            "exactly what the Content-Hub UI's Publish button sends."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "properties": {
                           "@id": {"type": "string", "description": "Widget IRI (`/api/3/widgets/<uuid>`)."},
                           "draft": {"type": "boolean", "description": "`false` to publish live; `true` for draft-only."},
                           "installed": {"type": "boolean", "description": "Set `true` on publish."},
                           "enablePublish": {"type": "boolean", "description": "Publish flag - send `false`."},
                           "replace": {"type": "boolean", "description": "Supersede the currently-installed version."},
                           "replaceVersions": {"type": "array", "items": {"type": "string"}, "description": "Versions to replace (usually empty)."},
                           "publishedDate": {"type": "integer", "description": "Epoch seconds (`int(time.time())`)."},
                       },
                       "description": "Development manifest with `tree` removed and publish flags added."},
        }}},
        "responses": {"200": _resp("The published widget record.")},
    },
}

PATHS["/api/3/widgets/export/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "post": {
        "tags": ["Widgets"],
        "summary": "Export a widget to .tgz",
        "description": (
            "Exports a widget as a `.tgz` archive. Body `{development: bool}` "
            "selects the development-workspace copy (`true`) or the "
            "installed/published one (`false`). Send `Accept: "
            "application/octet-stream` - the response is the raw archive bytes."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "properties": {
                "development": {"type": "boolean", "default": False, "description": "Export the development-workspace copy instead of the published one."},
            }},
            "example": {"development": False},
        }}},
        "responses": {"200": {
            "description": "Widget archive binary.",
            "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}, "example": "<binary>"}},
        }},
    },
}

PATHS["/api/3/delete/widgets"] = {
    "delete": {
        "tags": ["Widgets"],
        "summary": "Delete widget records",
        "description": (
            "Deletes one or more widget records by uuid. **Note the `/delete/` "
            "infix** in the path - this is not the standard `/api/3/widgets` "
            "collection. Body `{ids: [<uuid>]}`. 204 on success."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["ids"],
                       "properties": {"ids": {"type": "array", "items": {"type": "string", "format": "uuid"}, "description": "Widget uuids to delete."}}},
            "example": {"ids": [_UUID]},
        }}},
        "responses": {"204": _resp("Deleted.")},
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
for path, tag, summary, ref in [
    ("/api/3/roles", "Access management", "Roles", "Role"),
    ("/api/3/teams", "Access management", "Teams", "Team"),
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
                 "responses": {"201": _resp("Created.", ref=ref)}},
    }

# People records, password reset, per-user settings and saved insights are all
# captured from live lifecycles (throwaway user created -> password reset ->
# read -> updated -> deleted; throwaway insight and user setting created ->
# read -> updated -> deleted). pyfsr drives this whole surface.
PATHS["/api/3/people"] = {
    "get": {
        "tags": ["Access management"],
        "summary": "List users (People records)",
        "parameters": COMMON_QPARAMS,
        "description": (
            "Hydra-paged listing of the tenant's People records -- the user "
            "directory every das login (`/api/auth/users`) hangs off. "
            "`?userId=<das user uuid>` finds the record linked to a login "
            "(pyfsr's `UsersAPI.lookup`). pyfsr: `client.users.list()`."
        ),
        "responses": {
            "200": {
                "description": "Hydra collection of Person records.",
                "content": {"application/json": {"schema": {"allOf": [
                    {"$ref": "#/components/schemas/HydraCollection"},
                    {"type": "object", "properties": {"hydra:member": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/User"},
                    }}},
                ]}}},
            },
        },
    },
    "post": {
        "tags": ["Access management"],
        "summary": "Create a user (People record)",
        "description": (
            "Creates a People record and provisions the linked das login from "
            "the nested `user` block. The login stays passwordless until "
            "`POST /api/3/resetpassword` sets one, and an omitted "
            "`user.status` defaults the account to inactive. pyfsr: "
            "`client.users.create()`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/PersonCreate"}}}},
        "responses": {"201": _resp("Created Person record.", ref="User")},
    },
}

PATHS["/api/3/people/{uuid}"] = {
    "parameters": [{"name": "uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "People record uuid (from `GET /api/3/people`)."}],
    "get": {
        "tags": ["Access management"],
        "summary": "Get a user (People record)",
        "description": "Returns a single People record. Relationship fields (`roles`, `teams`, `user`) are null unless expanded. pyfsr: `client.users.get()`.",
        "responses": {"200": _resp("Person record.", ref="User"), "404": _err(404, "Not found.")},
    },
    "put": {
        "tags": ["Access management"],
        "summary": "Update a user (People record)",
        "description": (
            "Partial update of a People record (e.g. `department`, phones, "
            "`csActive` to deactivate and free the license seat -- pyfsr's "
            "`UsersAPI.deactivate`). pyfsr: `client.users.update()`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object",
                       "description": "Fields to update; partial record accepted. Common keys: `department`, `phoneWork`, `phoneMobile`, `title`, `description`, `csActive` (false deactivates and frees the license seat), `roles`, `teams`, `user.status`.",
                       "properties": {
                           "firstname": {"type": "string"},
                           "lastname": {"type": "string"},
                           "title": {"type": "string"},
                           "email": {"type": "string"},
                           "department": {"type": "string"},
                           "description": {"type": "string"},
                           "phoneWork": {"type": "string"},
                           "phoneMobile": {"type": "string"},
                           "csActive": {"type": "boolean", "description": "false deactivates the person (pyfsr's `UsersAPI.deactivate`)."},
                           "roles": {"type": "array", "items": {"type": "string"}, "description": "Role names, UUIDs or IRIs."},
                           "teams": {"type": "array", "items": {"type": "string"}},
                           "user": {"type": "object", "properties": {"status": {"type": "integer", "enum": [1, 2]}}},
                       }}}}},
        "responses": {"200": _resp("Updated Person record.", ref="User"), "404": _err(404, "Not found.")},
    },
    "delete": {
        "tags": ["Access management"],
        "summary": "Delete a user (People record)",
        "description": "Deletes the People record outright (live-verified 204). Most deployments deactivate instead via `PUT` with `csActive: false`.",
        "responses": {"204": {"description": "Deleted."}, "404": _err(404, "Not found.")},
    },
}

PATHS["/api/3/resetpassword"] = {
    "post": {
        "tags": ["Access management"],
        "summary": "Reset a user's application password",
        "description": (
            "Admin reset of another user's application password. das refuses "
            "resetting your own login this way -- use the change-password "
            "flow. `sendEmail` defaults to false. pyfsr: "
            "`client.users.reset_password()`."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/ResetPasswordRequest"}}}},
        "responses": {"200": {"description": "The bare JSON string \"Password Changed sucessfully\" (sic).",
                              "content": {"application/json": {"schema": {"type": "string"}}}}},
    },
}

PATHS["/api/3/insights"] = {
    "get": {
        "tags": ["AI Insight"],
        "summary": "List saved insights",
        "parameters": COMMON_QPARAMS,
        "description": "Hydra-paged listing of saved AI insights (may be empty when none are saved). pyfsr: `client.ai.insights`.",
        "responses": {
            "200": {
                "description": "Hydra collection of Insight records.",
                "content": {"application/json": {"schema": {"allOf": [
                    {"$ref": "#/components/schemas/HydraCollection"},
                    {"type": "object", "properties": {"hydra:member": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/InsightRecord"},
                    }}},
                ]}}},
            },
        },
    },
    "post": {
        "tags": ["AI Insight"],
        "summary": "Save a new insight",
        "description": "Saves an insight as an `insights` record bound to a plan execution (pyfsr: `client.ai.insights.save()`). `planid` is not FK-validated. The widget also creates a schedule for the insight, which this call does not do.",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/InsightSaveRequest"}}}},
        "responses": {"201": _resp("Created Insight record.", ref="InsightRecord")},
    },
}

PATHS["/api/3/insights/{insight_id}"] = {
    "parameters": [{"name": "insight_id", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"},
                    "description": "Insight uuid (from `GET /api/3/insights`)."}],
    "get": {
        "tags": ["AI Insight"],
        "summary": "Get a saved insight",
        "description": "Returns a single saved insight record by uuid, including its title, query, socrole, planid and schedule reference.",
        "responses": {"200": _resp("Insight record.", ref="InsightRecord"), "404": _err(404, "Not found.")},
    },
    "put": {
        "tags": ["AI Insight"],
        "summary": "Update a saved insight",
        "description": "Updates title/query/socrole/planid on an existing insight (pyfsr: `client.ai.insights.save(..., insight_id=...)`).",
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/InsightSaveRequest"}}}},
        "responses": {"200": _resp("Updated Insight record.", ref="InsightRecord"), "404": _err(404, "Not found.")},
    },
    "delete": {
        "tags": ["AI Insight"],
        "summary": "Delete a saved insight",
        "description": "Deletes the saved insight record outright (live-verified 204); the widget's schedule, if one was created, is not touched by this call.",
        "responses": {"204": {"description": "Deleted."}, "404": _err(404, "Not found.")},
    },
}

PATHS["/api/3/user_settings/current/{key}"] = {
    "parameters": [{"name": "key", "in": "path", "required": True, "schema": {"type": "string"},
                    "description": "Setting key; may contain slashes (e.g. `user/view/details/alerts/viewTemplate`)."}],
    "get": {
        "tags": ["Authentication"],
        "summary": "Get a per-user setting value",
        "description": "Returns the current user's stored value for `key` (arbitrary JSON). Unknown keys return 404. pyfsr: `client.user_settings.get()`.",
        "responses": {"200": {"description": "The stored value (arbitrary JSON).",
                              "content": {"application/json": {"schema": {}}}},
                      "404": _err(404, "Key not set.")},
    },
    "put": {
        "tags": ["Authentication"],
        "summary": "Set a per-user setting value",
        "description": "Stores the body as the current user's value for `key` (arbitrary JSON). pyfsr: `client.user_settings.set()`.",
        "requestBody": {"required": True, "content": {"application/json": {"schema": {
            "description": "The value to store (arbitrary JSON; FortiSOAR deep-merges it into the user's settings at `key`)."}}}},
        "responses": {"200": {"description": "The stored value (arbitrary JSON).",
                              "content": {"application/json": {"schema": {}}}}},
    },
    "delete": {
        "tags": ["Authentication"],
        "summary": "Delete a per-user setting",
        "description": "Removes the current user's stored value for `key`. Use to undo a custom setting and fall back to the platform default.",
        "responses": {"204": {"description": "Deleted."}, "404": _err(404, "Key not set.")},
    },
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
        "description": "**Replaces** the listed fields - values not in the payload that were previously set are overwritten with the new payload's values, so resend the full roles/teams lists you want to keep.",
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
        "description": "Lookup by the API-key user's uuid (the `userId` from `GET /api/3/api_keys`). Default response masks the key; pass `show_api_key=true` to retrieve the plaintext - only works when the key was created with `retrievable_mode` enabled.",
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
            "- `REVOKE` - permanent deactivation.\n"
            "- `ACTIVATE` / `DEACTIVATE` - toggle status.\n"
            "- `REGENERATE` - issue a fresh key; requires `api_key_validity`.\n"
            "- `RESET_VALIDITY` - extend/shorten validity; requires `api_key_validity`."
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
            "Toggle a single option by name/value. The notable API-key option is `retrievable_mode` - when "
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

# The /api/import/ namespace (no /3/) is parallel to /api/3/import_jobs above:
# the CRUD lives at /api/3/import_jobs, but option-generation + run-trigger
# happen here. Both are async - poll GET /api/3/import_jobs/{job_uuid} to track.
PATHS["/api/import/{job_uuid}"] = {
    "parameters": [{"name": "job_uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "get": {
        "tags": ["Import / export"],
        "summary": "Kick off async option generation",
        "description": (
            "Starts the server walking the uploaded bundle to build the "
            "import-options tree. **The response body is a progress log, "
            "not the options** - poll `GET /api/3/import_jobs/{job_uuid}` "
            "until the job's `options` field is populated (status becomes "
            "`\"Reviewing\"`)."
        ),
        "responses": {"200": _resp("Progress log (not the options - poll the job record).")},
    },
    "put": {
        "tags": ["Import / export"],
        "summary": "Trigger the import run (async)",
        "description": (
            "Triggers the import - the server applies the bundle (an upsert "
            "keyed by `config_id`). **Async:** poll `GET "
            "/api/3/import_jobs/{job_uuid}` until `status == \"Import "
            "Complete\"`. An import carrying module/schema changes drives the "
            "appliance through a backup + DB-migrate + cache-rebuild cycle "
            "(ride through transient 5xx / \"System Backup\" / \"Clearing "
            "Cache\" states)."
        ),
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {},
                       "description": "No request body - the job is identified by the path uuid."},
            "example": {},
        }}},
        "responses": {"200": _resp("Import job record (poll until `status == \"Import Complete\"`).")},
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


# --- Export templates ------------------------------------------------------
# Templates drive `PUT /api/export` - a reusable selection of what to export
# (record sets, picklists, connectors, playbooks). Create/delete templates
# here; trigger + poll via `PUT /api/export` + `GET /api/3/export_jobs/{uuid}`.

PATHS["/api/3/export_templates"] = {
    "post": {
        "tags": ["Import / export"],
        "summary": "Create an export template",
        "description": (
            "Creates a reusable export template. Body carries `name`, "
            "`options` (the selection of what to export - record sets, "
            "picklists, connectors, playbook collections), and optional "
            "`metadata` (defaults to `{autoSelectPicklists: true}`). The "
            "template's uuid is passed to `PUT /api/export?template=<uuid>` "
            "to trigger an export."
        ),
        "requestBody": {"required": True, "content": {"application/json": {
            "schema": {"type": "object", "required": ["name"],
                       "properties": {
                           "name": {"type": "string", "description": "Template display name."},
                           "options": {"type": "object", "description": "Export selection: record sets, picklistNames, connectors, playbooks, etc."},
                           "metadata": {"type": "object", "description": "Template metadata (default: `{autoSelectPicklists: true}`)."},
                       }},
            "example": {"name": "Alert backup",
                        "options": {"recordSets": [{"type": "alerts", "label": "Open alerts", "query": {"type": "alerts", "limit": 500}}]},
                        "metadata": {"autoSelectPicklists": True}},
        }}},
        "responses": {"200": _resp("The created export template record.")},
    },
}

PATHS["/api/3/export_templates/{template_uuid}"] = {
    "parameters": [{"name": "template_uuid", "in": "path", "required": True, "schema": {"$ref": "#/components/schemas/UUID"}}],
    "delete": {
        "tags": ["Import / export"],
        "summary": "Delete an export template",
        "description": "Deletes one export template by uuid. 204 on success.",
        "responses": {"204": _resp("Deleted.")},
    },
}

PATHS["/api/export"] = {
    "put": {
        "tags": ["Import / export"],
        "summary": "Trigger an export from a template",
        "description": (
            "Triggers a configuration export using a pre-created template. "
            "**Note: `/api/export` (no `/3/`).** The parameters are **query "
            "params, not a JSON body** - `fileName` (must end in `.zip`) and "
            "`template` (a template uuid from `POST /api/3/export_templates`). "
            "Returns the export-job record; poll `GET "
            "/api/3/export_jobs/{job_uuid}` until `status == \"Export "
            "Complete\"`, then download the `file` IRI."
        ),
        "parameters": [
            {"name": "fileName", "in": "query", "required": True, "schema": {"type": "string"},
             "description": "Output filename - must end in `.zip`."},
            {"name": "template", "in": "query", "required": True, "schema": {"type": "string", "format": "uuid"},
             "description": "Export template uuid (from `POST /api/3/export_templates`)."},
        ],
        "requestBody": {"required": False, "content": {"application/json": {
            "schema": {"type": "object", "properties": {},
                       "description": "No request body - the export is driven by the `fileName` and `template` query params above."},
            "example": {},
        }}},
        "responses": {"200": _resp("Export job record (poll until `status == \"Export Complete\"`).")},
    },
}


# --- Views & view templates (pyfsr-discovered) -----------------------------
#
# The FortiSOAR UI renders module list/detail pages from named "view templates"
# stored at /api/views/1/{name}. The "app" view is the left-hand navigation.

PATHS["/api/views/1/app"] = {
    "get": {"tags": ["Views"], "summary": "Get the app navigation view",
            "description": (
                "Returns the single view record describing the left-hand navigation. "
                "`config.navigation` holds the top-level sections. pyfsr: "
                "`client.views.app()`."
            ),
            "responses": {"200": _resp("Navigation view record.")}},
}

PATHS["/api/views/1/{name}"] = {
    "parameters": [
        {"name": "name", "in": "path", "required": True, "schema": {"type": "string"},
         "example": "modules-alerts-list",
         "description": (
             "View key, not a template name: `modules-<module>-<list|detail|form>`, "
             "`pages-<page>` (detail view), or a bare name such as `app`."
         )},
    ],
    "get": {"tags": ["Views"], "summary": "Get the layout for a view",
            "description": (
                "Returns the layout the caller sees for this view: their own saved copy "
                "(user view template) if they have one, otherwise the default system view "
                "template. A system template's display name (`Default Layout`, ...) is not a "
                "valid key and returns 404. To list system templates use "
                "`GET /api/3/system_view_templates`."
            ),
            "responses": {"200": _resp("View template record."), "404": {"description": "No template for that key."}}},
    "post": {"tags": ["Views"], "summary": "Save the caller's own layout for a view",
             "description": (
                 "Creates or updates the **caller's own** layout for the view (a user view "
                 "template); it does not create a system template, and other users keep theirs. "
                 "Same handler as PUT. Send `type`, `module`, `viewOptions`, `config` and "
                 "`isDefault: true`. The server only reads back a user copy whose `isDefault` is "
                 "true, so a copy saved without it is never used and the next write fails with "
                 "409 (`module, viewoptions, name, owner` must be unique). User view templates "
                 "cannot be deleted through the API."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object"},
                 "example": {"type": "rows", "module": "alerts", "viewOptions": "list",
                             "isDefault": True, "config": {}}}}},
             "responses": {"200": _resp("Saved view template."),
                           "400": {"description": "Missing body, or a required column such as `module`."},
                           "409": {"description": "A non-default copy already exists for this user."}}},
    "put": {"tags": ["Views"], "summary": "Update the caller's own layout for a view",
            "description": "Same handler and body as POST.",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
            "responses": {"200": _resp("Saved view template."),
                          "409": {"description": "A non-default copy already exists for this user."}}},
}


# --- Dynamic variables (pyfsr-discovered) ----------------------------------
#
# Global variables referenced in playbooks as {{ globalVars.<name> }}.

PATHS["/api/wf/api/dynamic-variable/"] = {
    "get": {"tags": ["Workflow tools"], "summary": "List global dynamic variables",
            "description": (
                "Returns every FortiSOAR global (\"dynamic\") variable. Each entry has "
                "`id`, `name`, `value`, `default_value`. Referenced in playbooks as "
                "`{{ globalVars.<name> }}`. pyfsr: `client.wf_tools.dynamic_variables()`."
            ),
            "responses": {"200": _resp("Array of variable records.")}},
    "post": {"tags": ["Workflow tools"], "summary": "Create a global dynamic variable",
             "description": (
                 "Create a new global variable. POSTing a name that already exists is an "
                 "error - use PUT to update. pyfsr: "
                 "`client.wf_tools.set_dynamic_variable(name, value)` (handles the "
                 "create-or-update upsert)."
             ),
             "requestBody": {"required": True, "content": {"application/json": {
                 "schema": {"type": "object", "required": ["name", "value"], "properties": {
                     "name": {"type": "string"},
                     "value": {"type": "string"},
                     "default_value": {"type": "string"},
                 }},
             }}},
             "responses": {"200": _resp("Created."), "409": {"description": "Name already exists."}}},
}


# --- Playbook execution internals (pyfsr-discovered) ----------------------
#
# Per-step execution records and the modern approval gate list endpoint.

PATHS["/api/wf/api/historical-steps/"] = {
    "get": {"tags": ["Playbook runs"], "summary": "List per-step execution records for a run",
            "description": (
                "Fetch per-step execution records for a playbook run, keyed by `task_id` "
                "(what `POST /api/wf/api/workflows/{pk}/start/` returns). Steps are ordered "
                "by creation time (oldest first). Only populates after a run completes. "
                "Query params: `limit` (default 200), `status`, `name`. pyfsr: "
                "`client.playbooks.historical_steps(task_id)`."
            ),
            "parameters": [
                {"name": "task_id", "in": "query", "schema": {"type": "string"},
                 "description": "Run task id."},
                {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200}},
                {"name": "status", "in": "query", "schema": {"type": "string"}},
                {"name": "name", "in": "query", "schema": {"type": "string"}},
            ],
            "responses": {"200": _resp("Array of step records.")}},
}

PATHS["/api/wf/api/manual-wf-input/"] = {
    "get": {"tags": ["Playbook runs"], "summary": "List pending manual-input / approval gates",
            "description": (
                "Returns all pending manual-wf-input records - the modern, resumable "
                "approval gates. Each record represents a paused playbook step awaiting "
                "a decision (approve/reject or manual data input). pyfsr: "
                "`client.playbooks.approval(run_pk)` resolves the pending input for a "
                "specific run."
            ),
            "responses": {"200": _resp("Array of pending manual-input records.")}},
}


# --- System: daily action count (pyfsr-discovered) ------------------------
#
# The workflow engine's license usage counter - the endpoint the UI's
# "Actions Remaining" badge reads.

PATHS["/api/wf/workflow/config/"] = {
    "get": {"tags": ["System"], "summary": "Daily action-count license usage",
            "description": (
                "Returns the workflow engine's decrypted license counters: "
                "`daily_action_limit`, `remaining_actions`, `reset_time`, "
                "`last_update_time`. `daily_action_limit` is the per-day cap "
                "(e.g. 10000 on FortiFlex Starter; `-1` means unlimited/unenforced). "
                "Counted steps are Create/Update Record, Connector Action, Set "
                "Variable, etc.; Wait/Approval/Loops/Reference-a-Playbook are not "
                "counted. pyfsr: `client.system.daily_action_count()`. "
                "Query param: `section=license` (the endpoint also serves other "
                "workflow config sections, but `license` is the useful one)."
            ),
            "parameters": [
                {"name": "section", "in": "query", "schema": {"type": "string", "enum": ["license"]},
                 "description": "Must be `license` to get the action-count data."},
            ],
            "responses": {"200": _resp("Daily action count record.")}},
}


# --- Change password (pyfsr-discovered) ------------------------------------

PATHS["/api/3/changepassword"] = {
    "put": {"tags": ["Access management"], "summary": "Change the calling user's password",
            "description": (
                "Changes the calling user's own application password. Body requires "
                "`uuid`, `loginId`, `oldPassword`, `newPassword` - `uuid` and `loginId` "
                "must be the caller's own (looked up via `GET /api/3/actors/current`). "
                "The new password must differ from the old one and pass the password "
                "policy. LDAP/SAML users cannot change their password through this "
                "endpoint. pyfsr: `client.users.change_password(old, new)` handles the "
                "whoami lookup automatically."
            ),
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "required": ["uuid", "loginId", "oldPassword", "newPassword"],
                 "properties": {
                     "uuid": {"type": "string", "format": "uuid"},
                     "loginId": {"type": "string"},
                     "oldPassword": {"type": "string", "description": "The current password."},
                     "newPassword": {"type": "string", "description": "The new password; must meet the password policy."},
                 }},
            }}},
            "responses": {"200": _resp("Password changed."), "400": {"description": "Policy violation or same password."}}},
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

# ---------------------------------------------------------------------------
# Spec assembly
# ---------------------------------------------------------------------------

TAG_GROUPS = [
    {"name": "Auth & system", "tags": ["Authentication", "System", "Notifications", "Access management"]},
    {"name": "Records", "tags": ["Records (generic)", "Bulk operations", "Alerts"]},
    {"name": "Modules", "tags": ["Modules"]},
    {"name": "Query", "tags": ["Query"]},
    {"name": "Automation", "tags": ["Run a playbook", "Playbook runs", "Scheduled tasks", "Connectors", "Agents", "Workflow tools"]},
    {"name": "Threat intel", "tags": ["Threat intel (TAXII)"]},
    {"name": "Audit", "tags": ["Audit"]},
    {"name": "Reference", "tags": ["Metadata", "Files", "Widgets", "Views", "Import / export"]},
]

TAG_DESCRIPTIONS = {
    "Authentication": "Sign in, sign out, and look up the current user / actor.",
    "System": "Build version, license info, HA cluster health, feature flags, and cache invalidation. The version + public-license endpoints are unauthenticated; the rest require auth.",
    "Notifications": (
        "Per-user system (bell-icon) notifications under "
        "`/api/rule/api/system-notification/`. Note the non-standard `/api/rule/` "
        "namespace and that the list endpoint is POST, not GET."
    ),
    "Records (generic)": (
        "Every module that stores records is available at `/api/3/<plural>` with the same list + create / get / "
        "update / delete shape (list responses are wrapped in a `hydra:member` envelope - see "
        "[Pagination & response shape](#description/pagination-response-shape)). The operations below - list / create "
        "on `/api/3/{collection}` and get / update / delete on `/api/3/{collection}/{uuid}` - document that shared "
        "shape. The **Alerts** endpoints are a worked example."
    ),
    "Alerts": "Concrete CRUD on the `alerts` collection - representative of every record module (`incidents`, `indicators`, `tasks`, `assets`, `people`, ...).",
    "Bulk operations": "High-throughput insert/update/delete/upsert and feed-ingest paths. Note: `/api/ingest-feeds/*` and `/api/insert-feeds/*` skip on-create playbook triggers; `POST /api/3/insert/*` does not.",
    "Query": "Three search surfaces: URL-param (AND only), POST `/api/query/*` body grammar (full AND/OR + aggregates), and global Elasticsearch (`/api/search`). See operation descriptions for when to use which.",
    "Audit": "Audit log search + retention. Returns one page at a time with no total count - call `/count` separately if you need it. Filters are top-level only and accept exactly one value.",
    "Playbook runs": "Track and control playbook runs after they start: status by `task_id`, run detail, step history, resume / retry / approve. Lives under `/api/wf/*`.",
    "Run a playbook": (
        "Start a playbook from the API. Pick the route by how the playbook is triggered:\n\n"
        "| Playbook's trigger | Route | pyfsr |\n"
        "|---|---|---|\n"
        "| Any (by playbook UUID; trigger conditions skipped) | `POST /api/triggers/1/notrigger/{workflowId}` | `client.playbooks.trigger(name_or_uuid)` |\n"
        "| Custom API Endpoint | `POST /api/triggers/1/{name}` | `client.playbooks.trigger_by_name(name)` |\n"
        "| Custom API Endpoint, run on a worker (202) - **not found on 8.0.0** | `POST /api/triggers/1/deferred/{name}` | `client.playbooks.trigger_by_name(name, deferred=True)` |\n"
        "| Manual (record action button) | `POST /api/triggers/1/action/{routeUuid}` | `client.playbooks.trigger_action(route_uuid, module=..., record_uuid=...)` |\n\n"
        "Every route answers with a `task_id`. Track it with `GET /api/wf/api/workflows/?task_id=<task_id>&parent_wf__isnull=True` "
        "(see **Playbook runs**), or call `client.playbooks.run_and_wait(...)`. Worked example: "
        "[Triggering a playbook with an API key and tracking the task](#description/triggering-a-playbook-with-an-api-key-and-tracking-the-task)."
    ),
    "Scheduled tasks": (
        "Workflow-engine periodic jobs under `/api/wf/api/scheduled/` - the "
        "platform-shipped schedules (Reclaim Disk Space, Purge Executed Playbook "
        "Logs, Archive Data) plus user-created cron schedules that run a playbook. "
        "Each row is a periodic task with a nested `crontab` and a `kwargs.wf_iri` "
        "pointing at the workflow. The row `id` is a per-request Fernet token - "
        "resolve by `name` for any non-immediate use."
    ),
    "Connectors": (
        "Full connector lifecycle. Per-action request shape comes from each connector's `info.json`.\n\n"
        "**Flow - install → configure → execute → uninstall:**\n\n"
        "1. **Install from `.tgz`** - `POST /api/3/solutionpacks/install?$type=connector&$replace=true` (multipart, field `file` = the binary). Response carries the integer connector `id`.\n"
        "2. **Create a config** - `POST /api/integration/configuration/` with `name`, `connector` (integer id from step 1), and `config` (the connector's field values). Add `agent` only if you want the connector to run on a **remote agent**; omit it to use the appliance's self-agent. Response carries `config_id` (uuid).\n"
        "3. **Execute an action** - `POST /api/integration/execute/` with `connector` name, `version`, `operation`, `config` (the uuid from step 2), and `params`.\n"
        "4. **Health-check** - `GET /api/integration/connectors/healthcheck/{name}/{version}/?config=<uuid>` for the cheap variant (uses an existing config), or the POST form when re-sending a full config inline.\n"
        "5. **Cleanup** - `DELETE /api/integration/configuration/{config_id}/` (uuid + trailing slash), then `DELETE /api/integration/connectors/{id}/` (integer id + trailing slash). The trailing slash is mandatory - without it you'll see `403 Could not validate HMAC fingerprint`.\n\n"
        "**Targeting a remote agent:** to run a connector on a remote agent instead of the self-agent, "
        "either include `agent` in the `POST /api/integration/configuration/` body (existing config on a "
        "remote agent), or use the dedicated remote-install routes: "
        "`POST /api/integration/install-connector/` with `name`, `version`, `agent_id` to push the "
        "connector to a specific agent; `PUT` to upgrade and `DELETE` to uninstall on the same path. "
        "`GET /api/integration/connectors/agents/{name}/{version}/` lists which agents already have the "
        "connector installed, and `GET /api/integration/agent-heartbeat/{agent}/` probes the SME bus to "
        "that agent."
    ),
    "Agents": (
        "Remote-agent records, SME router discovery, and the per-agent installer download.\n\n"
        "**Flow - discover router → create agent → download installer → verify:**\n\n"
        "1. **Find the router** - `GET /api/3/routers` and read the first member's `@id` (router IRI) "
        "and `certificate` (CA PEM for the agent VM). Empty collection means SME is not enabled on "
        "the master; run `sudo csadm secure-message-exchange enable` first.\n"
        "2. **Create the record** - `POST /api/3/agents` with `name`, `router` (IRI from step 1), and "
        "`installerType` (bash or docker picklist IRI). Response carries `uuid`, `agentId`, "
        "`encryptionKey`, `username`, `password`, `vhost` - **the secrets are returned only once**.\n"
        "3. **Download the installer** - `POST /api/integration/agent-installer/` with the `agentId` "
        "from step 2. Response is a binary installer (`application/octet-stream`).\n"
        "4. **Verify** - poll `GET /api/3/agents/{uuid}` until `configurationHealth.itemValue` reaches "
        "`Remote Node Connected`. New records start in `Awaiting Remote Node Connection`.\n\n"
        "**Self-agent constants:** the appliance's own Self agent record is hardcoded at uuid "
        "`973c17df-bb4b-41e5-b59c-a408666fdf27` on every install (the parent tenant uuid is "
        "`b3a700f7-00be-4ef9-90c6-3c8fe6e1be63`). Its `agentId` - the runtime `masterId` - varies "
        "per appliance; read it from `GET /api/3/agents/{self-uuid}`."
    ),
    "Modules": (
        "Module and field schema: discover the published data model (`model_metadatas`), edit "
        "drafts in staging (`staging_model_metadatas`), and commit changes appliance-wide with "
        "`PUT /api/publish`. Each module is a staging record with an `attributes` list; every "
        "field has a storage `type` (the column kind) and a display `formType` (the editor "
        "widget) - two distinct axes. Publish is **appliance-wide**, not per-module: one "
        "`PUT /api/publish` promotes every pending staged change across the whole instance. See "
        "the [Modules](#description/modules) introduction for the staging/publish model and "
        "field-type rules."
    ),
    "Metadata": "Picklist taxonomies + values, Hydra `@context` type docs, and the auto-generated full API listing (handy for discovering endpoints not documented here).",
    "Files": "Attachment upload. Required as the first step of import-job ingestion.",
    "Widgets": (
        "Widget upload (shared with the connector install path), publish, "
        "export, and delete. The publish step loads the development manifest "
        "and PUTs it back with publish flags - the same flow the Content-Hub "
        "UI's Publish button drives."
    ),
    "Views": (
        "View templates that control how module list and detail pages render. "
        "`GET /api/views/1/app` returns the left-hand navigation; "
        "`/api/views/1/{name}` is the per-template CRUD surface."
    ),
    "Workflow tools": (
        "Global (\"dynamic\") variables referenced in playbooks as "
        "`{{ globalVars.<name> }}`. List and create via "
        "`/api/wf/api/dynamic-variable/`."
    ),
    "Access management": (
        "API keys, roles, teams.\n\n"
        "**Flow - create → bind → use → lifecycle → revoke:** run steps 1, 2, 4 and 5 with a JWT. "
        "An API key cannot manage keys: `/api/auth/*` refuses it, and so does creating or changing "
        "an `api_keys` binding.\n\n"
        "1. **Create the API-key user** - `POST /api/auth/users` with body `{\"type\": 9, \"status\": 1, \"api_key_validity\": <1..365>}`. All three are integers - the published PDF shows quoted strings, which the appliance rejects with 400. Response carries the user `uuid` and the plaintext key.\n"
        "2. **Bind it to roles and teams** - `POST /api/3/api_keys` with `name`, `roles` (IRIs), `teams` (IRIs), and `userId` (the uuid from step 1). Required to make the key actually usable.\n"
        "3. **Read the scope** - `GET /api/3/api_keys/{uuid}` for one binding, or `GET /api/3/api_keys` for the full list.\n"
        "4. **Lifecycle operations** - `PUT /api/auth/users` with `uuid`, `key_type: API_KEY`, and `operation` ∈ `{REVOKE, ACTIVATE, DEACTIVATE, REGENERATE, RESET_VALIDITY}`. `REGENERATE` and `RESET_VALIDITY` also need `api_key_validity`.\n"
        "5. **Bulk fetch with plaintext** - `POST /api/auth/query/users` with `{users: [<uuid>, ...], show_api_key: true}` (only returns plaintext for keys whose user was created with `retrievable_mode` enabled in `/api/auth/config`)."
    ),
    "Import / export": "Configuration import/export. Read the `import_jobs` description carefully - the inline-envelope shape is a silent no-op.",
    "Threat intel (TAXII)": (
        "TAXII 2.1 server exposing FortiSOAR threat-intel collections (FortiGuard feeds, block lists, "
        "and any custom collections you create). Discovery lives at `/api/taxii/1/`; collections, "
        "objects, and manifest endpoints follow.\n\n"
        "The server is **read-only**: every default collection advertises `can_write: false` and "
        "`POST` to `objects/` is not routed, and there is no STIX bundle ingest route. To push "
        "threat intel into FortiSOAR, map it to module rows and use "
        "`POST /api/ingest-feeds/{module}`.\n\n"
        "Response envelope for `objects/` and `manifest/` is `{totalItems, objects: []}` - a "
        "FortiSOAR-specific shape, not the standard TAXII 2.1 `more` / `next` cursor. Paginate with "
        "`?limit=` and `?added_after=<ISO-8601>`.\n\n"
        "All responses use `Content-Type: application/taxii+json;version=2.1`; collection "
        "`media_types` advertise `application/stix+json;version=2.1`."
    ),
}


REFERENCE_PROSE = r"""A hand-shaped OpenAPI 3.1 reference for the FortiSOAR REST API.

> **Official docs:** [FortiSOAR API Guide on docs.fortinet.com](https://docs.fortinet.com/document/fortisoar/latest/api-guide/846127). This reference is **not** official Fortinet documentation - it's a community project. Consult the official guide for the authoritative surface; use this site for endpoints that the guide doesn't cover or where live-verified shapes are useful.

> **Disclaimer.** This reference is a community effort and is **not exhaustive**. Coverage is the surface I use day-to-day; many operations are still missing. Request/response examples marked live-captured came from a real FortiSOAR; the rest are documented from the API guide and DB introspection only and are best-effort. Always validate against your own appliance before relying on it.

Pills under each operation's title show which credentials it accepts - see [Authentication](#description/authentication).

## Concepts

Responses follow the **JSON-LD + Hydra** convention. In practice that means every record has an `@id` URL you can copy and reuse as a reference, plus an `@type` (the module name) and `@context` (model URL). List endpoints wrap their results in a `hydra:member` envelope - see [Pagination & response shape](#description/pagination-response-shape).

- **IRI** - a relative URL like `/api/3/alerts/<uuid>`. Treat it as a foreign-key pointer: wherever JSON references another record, that's what you'll see. The server generates `@id` on insert; clients should not send it.
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

Some endpoints accept only one method. Each operation carries pills next to its title, measured against live FortiSOAR:

- **API key** / **JWT** in green - that credential works. In red and struck through - it does not.
- **Not tested** - the call is too destructive to run against a live box, so it is unverified.
- **Not found** - the route answers 404 to every credential, so it does not exist on the versions measured.
- A blue version pill (**8.0.1+**) - the FortiSOAR version that introduced the operation.

Calls that need no credential (`POST /auth/authenticate`, `/api/version`, `/api/public/license`) have no pills.

The operation's lock icon / auth selector lists only the methods in green.


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
| `$relationships` | `false` | Controls whether linked modules appear in the response. When `true`, related collections (e.g. an alert's `tasks`, `indicators`, `assets`) are populated. When `false`, those collections are **left out entirely** - not returned as empty arrays. Single-value links (`severity`, `status`, `createUser`, etc.) are always returned as full record objects regardless of this flag. |
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
| URL-param | `GET /api/3/<resource>?...` | single AND chain | none | Simple lookups; everything ANDs together |
| Body | `POST /api/query/<resource>` | nested AND/OR groups | yes | Anything non-trivial; complex filters; counts |
| Global | `POST /api/search` | keyword `q` | none | Cross-module text search (Elasticsearch) |

### Request body shape

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

### Field operators

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
- `400 TypeError` from this route means the downstream `cyops-search` MQ consumer is unhealthy, not that the body shape is wrong. Check `systemctl status cyops-search` on the appliance.

### Persisted queries

Persisted queries are stored in `/api/3/queries` (ad-hoc), `/api/3/system_queries` (system-owned), and `/api/3/user_queries` (user-saved). They're *inputs* you copy into the body of `POST /api/query/<resourceShortName>` - there is no separate execute route that takes a query ID. To run a saved query, GET the query record and POST its body to `/api/query/<shortName>`. (`POST /api/query/<shortName>/<id>/<field>` is a related but distinct endpoint - relationship-walk on a record, not query execute.)

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
9. **JWT lifetime is short.** Default ~30 min; long-running syncs need to re-auth on 401, or use an API key where the operation takes one.

The 45-value `operation` enum is in the `AuditOperation` schema; fetch it dynamically from `GET /api/gateway/audit/operations`.

## Workflows & triggers

Run control lives under `/api/wf/*`. The endpoints below cover the most common control flows; less-used ones (`historical-workflows/*`, `expressions/*`, `dynamic-variable/*`) are tracked as a future expansion.

- `POST /api/wf/api/workflows/{pk}/start/` - manually queue.
- `POST /api/wf/api/workflows/{pk}/resume/` - resume a `paused` run. **Not for `awaiting`** manual-input runs - those use `wfinput_resume` (below).
- `GET /api/wf/api/workflows/{pk}/retry/` - retry a failed run from the failed step. **GET, not the guide's POST** (POST answers 405 on 8.0.0).
- `POST /api/wf/api/workflows/{pk}/approval/` - approval-step shortcut.

**Resuming an `awaiting` manual-input run** (verified live end-to-end; the run advances to `finished`):

1. `GET /api/wf/api/workflows/{run_pk}/?step_detail=true` → the run's awaiting execution-step ids (the correlation anchor).
2. `POST /api/wf/api/manual-wf-input/list_wfinput/` → the pending input whose `step_id` is one of those ids → `manual_input_id`. (`workflow` on the list member is an *encrypted* token, not the run pk, so `step_id` is the only honest link.)
3. `POST /api/wf/api/manual-wf-input/{manual_input_id}/retrieve_wfinput/` → `response_mapping.options[]` (the buttons; each has a `step_iri`).
4. `POST /api/wf/api/workflows/{run_pk}/wfinput_resume/` with `{input, step_iri: <chosen option's step_iri>, step_id, manual_input_id}` (add `approved: <bool>` for `is_approval` gates).

**Correction (was wrong here before):** `wfinput_resume` is the **real** path - it is NOT a decoy. `PUT /api/wf/api/manual-wf-input/{id}/` returns 200 but does **not** advance the run; don't use it to resume.

**Simpler linkage (live-verified on 8.0.0-6034):** the plain `GET /api/wf/api/manual-wf-input/` collection rows carry `workflow` as the **numeric run pk** (e.g. `144042`) - the same pk `wfinput_resume` wants - so a script that triggered the run itself can match its pending input by run pk alone, no `step_detail` correlation needed. `user` on the resume body is a `/api/3/people` IRI (resolve an admin from `GET /api/3/people`); omitting it 500s.

### Triggers

Three ways to fire a playbook from outside:

- **`POST /api/triggers/1/{name}`** - hits a Custom API Endpoint trigger (named via the trigger config). Allows alternate auth (Basic / no-auth) for external webhooks, by design - keeps the core API token-locked while letting webhook senders use simpler auth.
- ~~`POST /api/triggers/1/deferred/{name}`~~ - documented as the async variant (202) but **not routed on 8.0.0**: every name 404s before authentication. Use the sync route above.
- **`POST /api/triggers/1/notrigger/{workflowId}`** - direct execution of a workflow by UUID, bypassing trigger conditions. Useful for testing.
- **`POST /api/triggers/1/action/{routeUuid}`** - record-context execution via an action trigger's `route` uuid (from the playbook definition's trigger step). Answers `{"task_ids": [...]}` (plural), unlike `notrigger`'s scalar `task_id`.

The notifier service has additional fan-out via STOMP-over-WebSocket at `/websocket/` (server pushes workflow updates on `/topic/workflows/`). No REST surface; out of scope here.

### Triggering a playbook with an API key and tracking the task

Worked end-to-end flow against a Custom API Endpoint trigger: fire the playbook, capture the `task_id`, poll the workflow log until it reaches a terminal state, then fetch full execution details. The `deferred/` variant is not routed on 8.0.0; `notrigger/<workflowId>` and `action/<routeUuid>` fire with the same pattern (only the trigger URL changes).

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
 - **API-KEY vs Bearer.** An API key lasts for its validity period (1 to 365 days, set when it is created), so it suits long-running tracker scripts; a JWT typically dies after ~30 minutes mid-poll.

## Modules

A **module** is FortiSOAR's unit of schema: a named table with a list of fields
("attributes"). Every record collection (`alerts`, `incidents`, custom modules) is
backed by a module definition. The schema lives in two stores, and a third endpoint
moves changes between them:

- **Staging** (`/api/3/staging_model_metadatas`) - the editable draft. Creating a module
  or changing a field edits staging only; nothing is live yet.
- **Published** (`/api/3/model_metadatas`) - the committed schema records are read from.
  `GET /api/3/model_metadatas` is the drift-resistant source of truth for what fields a
  module actually has on this appliance.
- **Publish** is a single appliance-wide `PUT /api/publish` that promotes *all* pending
  staged changes to live. It is **not per-module** - one illegally-named draft anywhere
  can fail the whole migrate, so validate drafts before publishing.

### Field types - two axes

Every field (attribute) carries a **storage type** (`type`) and a **display type**
(`formType`). These are different axes and a correct field needs both:

- `type` is the column kind the platform stores: `string`, `integer`, `float`,
  `boolean`, `picklists`, `object`, `array`, or a target module type for a relationship.
  There is **no `text` storage type** - text-like fields store `string`. Publishing a
  field whose `type` is `text` fails validation ("Attribute type 'text' does not
  exist").
- `formType` is the editor widget: `text`, `textarea`, `richtext`, `html`, `email`,
  `url`, `phone`, `password`, `filehash`, `ipv4`, `ipv6`, `domain`, `file`, `integer`,
  `decimal`, `datetime`, `checkbox`, `json`, `object`, `picklist`,
  `multiselectpicklist`, `lookup`, `manyToMany`, `oneToMany`.

A `lookup` is a one-directional many-to-one pointer (no reverse field is created). A
`manyToMany` is a collection relationship; with the **default** inverse the platform
auto-creates the reverse field, with a **custom** `inversedField` you create the mirror
yourself. A `oneToMany` needs a matching `lookup` on its target - it will not publish
without one.

### Publish blast radius

Publish is synchronous in effect but asynchronous in execution - the PUT only *starts*
the migrate; the backup + commit then runs server-side, during which some surfaces may
be briefly unavailable. The impact is version- and change-dependent:

- On older builds every publish - even a no-op - runs the full backup + migrate + cache
  rebuild, during which the entire `/api/3` surface returns 503 for the whole window
  (~50-57s observed).
- On newer builds the impact is greatly reduced. A minor field-only edit (toggling
  *visibility* or setting *required-by-condition*) commits in ~3s with no observable
  outage. A **structural** change (adding a field/module) takes longer (~30s) and
  disrupts only the *record/query layer*: record-list endpoints return transient 404
  for ~13s and `/api/query` returns 400/401 for ~2.5s while the migrate runs - **not** a
  global 503. Module-metadata, view-resolve, and picklist surfaces stay available
  throughout. That record-layer blip is instance-wide, not scoped to the changed module.

`GET /api/publish/error` reports the last publish's status
(`{"status": "Success"|"Failed"|..., "last_publish_time": <epoch>}`) - it returns HTTP
400 (rather than 200) when a prior error is on record, with the same JSON body, so poll
it status-agnostically until `last_publish_time` advances.

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
      schema and no curated example, leave the response example unset - we
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
# live captures - this is the floor, not the ceiling.
# ---------------------------------------------------------------------------

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

    # Bulk ops - insert/update want a `data`-wrapped envelope on 8.0.0
    # (live-verified); delete is broken on every probed build.
    ("POST", "/api/3/insert/{moduleType}"): {
        "request": {"data": [
            {"name": "alert-001", "source": "Splunk", "sourceId": "spl-1001"},
            {"name": "alert-002", "source": "Splunk", "sourceId": "spl-1002"},
        ]},
        "response": {"201": {
            "@type": "hydra:Collection",
            "hydra:member": [
                {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
                 "uuid": _UUID, "name": "alert-001", "source": "Splunk", "sourceId": "spl-1001"},
                {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID2}", "@type": "Alert",
                 "uuid": _UUID2, "name": "alert-002", "source": "Splunk", "sourceId": "spl-1002"},
            ],
            "hydra:totalItems": 2,
        }},
    },
    ("PUT", "/api/3/update/{moduleType}"): {
        "request": {"data": [{"@id": f"/api/3/alerts/{_UUID}", "severity": "/api/3/picklists/high-uuid"}]},
        "response": {"200": {
            "@type": "hydra:Collection",
            "hydra:member": [
                {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
                 "uuid": _UUID, "name": "alert-001", "severity": "High"},
            ],
            "hydra:totalItems": 1,
        }},
    },
    ("DELETE", "/api/3/delete/{moduleType}"): {
        "request": [f"/api/3/alerts/{_UUID}", f"/api/3/alerts/{_UUID2}"],
        "response": {"200": {"totalCount": 2, "successCount": 2, "failureCount": 0}},
    },
    ("POST", "/api/3/upsert/{moduleType}"): {
        "request": {"sourceId": "spl-1001", "name": "alert-001-updated", "source": "Splunk"},
        "response": {"201": {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID}",
                              "@type": "Alert", "uuid": _UUID,
                              "name": "alert-001-updated", "source": "Splunk"}},
    },
    ("POST", "/api/3/bulkupsert/{moduleType}"): {
        "request": [{"sourceId": "spl-1001", "name": "alert-001"},
                     {"sourceId": "spl-1002", "name": "alert-002"}],
        "response": {"201": {
            "@type": "hydra:Collection",
            "hydra:member": [
                {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID}", "@type": "Alert",
                 "uuid": _UUID, "name": "alert-001", "sourceId": "spl-1001"},
                {"@context": "/api/3/contexts/Alert", "@id": f"/api/3/alerts/{_UUID2}", "@type": "Alert",
                 "uuid": _UUID2, "name": "alert-002", "sourceId": "spl-1002"},
            ],
            "hydra:totalItems": 2,
        }},
    },
    ("POST", "/api/ingest-feeds/indicators"): {
        "request": {"data": [{"value": "192.0.2.50"}, {"value": "evil.example.com"}]},
        "response": {"200": {"status": "success", "uuids": [_UUID, _UUID2]}},
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

    # --- Scheduled tasks ---
    ("GET", "/api/wf/api/scheduled/"): {
        "response": {"200": {
            "hydra:member": [
                {
                    "id": "gAAAAABkXyQ_placeholder_fernet_token",
                    "name": "nightly-recon",
                    "task": "workflow.tasks.periodic_task",
                    "enabled": True,
                    "crontab": {"id": 42, "minute": "7", "hour": "2",
                                "day_of_week": "*", "day_of_month": "*",
                                "month_of_year": "*", "timezone": "UTC"},
                    "kwargs": {"wf_iri": f"/api/3/workflows/{_PB_UUID}",
                               "exit_if_running": True, "timezone": "UTC",
                               "utcOffset": "UTC+00:00", "name": "nightly-recon",
                               "description": "nightly-recon", "auth": None,
                               "schedule_entry_name": "nightly-recon"},
                    "schedule_id": 7, "expires": None, "start_time": None,
                },
                "... <2 more rows truncated>",
            ],
            "hydra:totalItems": 3,
        }},
    },
    ("POST", "/api/wf/api/scheduled/"): {
        "request": {
            "name": "nightly-recon",
            "crontab": {"minute": "7", "hour": "2", "day_of_week": "*",
                        "day_of_month": "*", "month_of_year": "*", "timezone": "UTC"},
            "kwargs": {"exit_if_running": True,
                       "wf_iri": f"/api/3/workflows/{_PB_UUID}",
                       "timezone": "UTC", "utcOffset": "UTC+00:00"},
            "expires": None, "start_time": None, "enabled": True,
        },
        "response": {"201": {
            "id": "gAAAAABkXyQ_placeholder_fernet_token",
            "name": "nightly-recon",
            "task": "workflow.tasks.periodic_task",
            "enabled": True,
            "crontab": {"id": 42, "minute": "7", "hour": "2",
                        "day_of_week": "*", "day_of_month": "*",
                        "month_of_year": "*", "timezone": "UTC"},
            "kwargs": {"wf_iri": f"/api/3/workflows/{_PB_UUID}",
                       "exit_if_running": True, "timezone": "UTC",
                       "utcOffset": "UTC+00:00", "name": "nightly-recon",
                       "description": "nightly-recon", "auth": None,
                       "schedule_entry_name": "nightly-recon"},
            "schedule_id": 7, "expires": None, "start_time": None,
        }},
    },
    ("PUT", "/api/wf/api/scheduled/{id}/"): {
        "request": {
            "id": "gAAAAABkXyQ_placeholder_fernet_token",
            "name": "nightly-recon",
            "task": "workflow.tasks.periodic_task",
            "enabled": False,
            "crontab": {"id": 42, "minute": "7", "hour": "2",
                        "day_of_week": "*", "day_of_month": "*",
                        "month_of_year": "*", "timezone": "UTC"},
            "kwargs": {"wf_iri": f"/api/3/workflows/{_PB_UUID}",
                       "exit_if_running": True, "timezone": "UTC",
                       "utcOffset": "UTC+00:00", "name": "nightly-recon",
                       "description": "nightly-recon", "auth": None,
                       "schedule_entry_name": "nightly-recon"},
            "schedule_id": 7, "expires": None, "start_time": None,
        },
        "response": {"200": {
            "id": "gAAAAABkXyQ_placeholder_fernet_token",
            "name": "nightly-recon", "enabled": False,
        }},
    },
    ("DELETE", "/api/wf/api/scheduled/{id}/"): {"response": {"204": None}},
    ("POST", "/api/wf/api/scheduled/trigger-now/"): {
        "request": {"id": "gAAAAABkXyQ_placeholder_fernet_token"},
        "response": {"200": {"message": "The associated workflow is successfully triggered"}},
    },

    # --- Picklist writes ---
    ("POST", "/api/3/picklist_names"): {
        "request": {"name": "IncidentPhase", "system": False},
        "response": {"201": {
            "@context": "/api/3/contexts/PicklistName",
            "@id": f"/api/3/picklist_names/{_UUID}", "@type": "PicklistName",
            "uuid": _UUID, "name": "IncidentPhase", "system": False,
        }},
    },
    ("POST", "/api/3/picklists"): {
        "request": {"itemValue": "Contained",
                     "listName": f"/api/3/picklist_names/{_UUID}",
                     "color": "#4CAF50", "orderIndex": 2},
        "response": {"201": {
            "@context": "/api/3/contexts/Picklist",
            "@id": f"/api/3/picklists/{_UUID2}", "@type": "Picklist",
            "uuid": _UUID2, "itemValue": "Contained",
            "listName": f"/api/3/picklist_names/{_UUID}",
            "color": "#4CAF50", "orderIndex": 2,
        }},
    },
    ("DELETE", "/api/3/picklist_names/{uuid}"): {"response": {"204": None}},
    ("DELETE", "/api/3/picklists/{uuid}"): {"response": {"204": None}},

    # --- Notifications ---
    ("POST", "/api/rule/api/system-notification/notifications/"): {
        "request": {},
        "response": {"200": {
            "hydra:member": [
                {"uuid": _UUID,
                 "content": "<p>A task, Notify asset owner, has been assigned to you.</p>",
                 "entity_type": "tasks", "read": False, "createDate": 1736380800},
                {"uuid": _UUID2,
                 "content": "<p>Approval requested for Phishing Response.</p>",
                 "entity_type": "approvals", "read": True, "createDate": 1736380900},
            ],
            "hydra:totalItems": 2,
        }},
    },
    ("POST", "/api/rule/api/system-notification/purge/"): {
        "request": {},
        "response": {"200": {"result": "System Notification purge started", "status": "started"}},
    },

    # --- Tier 2: manual-input delete, widget writes, export template mgmt ---
    ("DELETE", "/api/wf/api/manual-wf-input/{pk}/"): {"response": {"204": None}},

    ("GET", "/api/3/widgets/development/{uuid}"): {
        "response": {"200": {
            "hydra:member": [{
                "@id": f"/api/3/widgets/{_UUID}", "@type": "WidgetRecord",
                "uuid": _UUID, "name": "accessControl", "version": "2.1.0",
                "draft": True, "installed": False, "published": False,
                "tree": {"...": "(stripped on publish)"},
            }],
            "hydra:totalItems": 1,
        }},
    },
    ("PUT", "/api/3/widgets/{uuid}"): {
        "request": {
            "@id": f"/api/3/widgets/{_UUID}", "name": "accessControl",
            "version": "2.1.0", "draft": False, "installed": True,
            "enablePublish": False, "replace": True, "replaceVersions": [],
            "publishedDate": 1736380800,
        },
        "response": {"200": {
            "@id": f"/api/3/widgets/{_UUID}", "@type": "WidgetRecord",
            "uuid": _UUID, "name": "accessControl", "version": "2.1.0",
            "draft": False, "installed": True, "published": True,
            "publishedDate": 1736380800,
        }},
    },
    ("POST", "/api/3/widgets/export/{uuid}"): {
        "request": {"development": False},
    },
    ("DELETE", "/api/3/delete/widgets"): {
        "request": {"ids": [_UUID]},
        "response": {"204": None},
    },
    ("POST", "/api/3/export_templates"): {
        "request": {
            "name": "Alert backup",
            "options": {"recordSets": [{"type": "alerts", "label": "Open alerts", "query": {"type": "alerts", "limit": 500}}]},
            "metadata": {"autoSelectPicklists": True},
        },
        "response": {"200": {
            "@id": f"/api/3/export_templates/{_UUID}", "@type": "ExportTemplate",
            "uuid": _UUID, "name": "Alert backup",
        }},
    },
    ("DELETE", "/api/3/export_templates/{template_uuid}"): {"response": {"204": None}},
    ("PUT", "/api/export"): {
        "response": {"200": {"@id": f"/api/3/export_jobs/{_UUID2}", "uuid": _UUID2,
                              "status": "Queued", "createDate": 1736380800}},
    },

    # --- Tier 3: import alternate namespace ---
    ("GET", "/api/import/{job_uuid}"): {
        "response": {"200": {
            "job_id": _UUID,
            "status": "InProgress",
            "progress": [{"step": "Extracting bundle", "status": "done"},
                         {"step": "Building options tree", "status": "running"}],
        }},
    },
    ("PUT", "/api/import/{job_uuid}"): {
        "request": {},
        "response": {"200": {"@id": f"/api/3/import_jobs/{_UUID}", "uuid": _UUID,
                             "status": "Import In Progress", "createDate": 1736380800}},
    },

    # --- Module editor: create a module in staging (staged until PUT /api/publish) ---
    ("POST", "/api/3/staging_model_metadatas"): {
        "request": {
            "type": "reconciliation_result",
            "module": "reconciliation_result",
            "tableName": "reconciliation_result",
            "displayName": "{{ name }}",
            "descriptions": {"singular": "Reconciliation Result",
                             "plural": "Reconciliation Results"},
            "ownable": True, "userOwnable": True,
            "system": False,
            "attributes": [
                {"name": "name", "type": "string", "formType": "text",
                 "descriptions": {"singular": "Name"}, "displayName": "{{ name }}",
                 "validation": {"required": True, "minlength": 0, "maxlength": 10485760},
                 "collection": False, "searchable": True, "gridColumn": True,
                 "readable": True, "writeable": True},
                {"name": "status", "type": "picklists", "formType": "picklist",
                 "descriptions": {"singular": "Status"},
                 "dataSource": {"model": "picklists", "query": {"logic": "AND",
                  "filters": [{"field": "listName__name", "operator": "eq",
                               "value": "ReconciliationStatus"}]}},
                 "collection": False, "gridColumn": True,
                 "readable": True, "writeable": True},
            ],
        },
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
    # Modules - schema discovery + module editor + publish
    "/api/3/model_metadatas": "[Modules](#description/modules)",
    "/api/3/model_metadatas/{uuid}": "[Modules](#description/modules)",
    "/api/3/staging_model_metadatas": "[Modules](#description/modules)",
    "/api/3/staging_model_metadatas/{uuid}": "[Modules](#description/modules)",
    "/api/publish": "[Publish blast radius](#description/publish-blast-radius)",
    "/api/publish/revert": "[Modules](#description/modules)",
    "/api/publish/error": "[Publish blast radius](#description/publish-blast-radius)",
    # Query
    "/api/query/{collection}": "[Query reference](#description/query-reference)",
    "/api/query/{collection}/{id}/{field}": "[Persisted queries](#description/query-reference) (Query reference -> Persisted queries)",
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
    "/api/triggers/1/{name}": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/triggers/1/deferred/{name}": "[Workflows & triggers](#description/workflows-triggers)",
    "/api/triggers/1/notrigger/{workflowId}": "[Workflows & triggers](#description/workflows-triggers)",
    # Imports
    "/api/3/import_jobs": "[Imports & exports](#description/imports-exports)",
    "/api/import/{job_uuid}": "[Imports & exports](#description/imports-exports)",
    "/api/3/export_jobs": "[Imports & exports](#description/imports-exports)",
    "/api/3/files": "[Imports & exports](#description/imports-exports) (file upload is step 1 of import)",
    # Auth
    "/auth/authenticate": "[Authentication](#description/authentication)",
    "/api/auth/cluster/health": "[Authentication](#description/authentication)",
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
        # value, so we don't ban it - only the service:port form.
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


# Examples show the shape, not the data: every list keeps LIST_CAP items, and a
# response string (alert sourcedata, LLM prompts, MITRE descriptions) keeps
# STRING_CAP characters. The spec is parsed in the browser on every page load,
# so its size is load time.
LIST_CAP = 2
STRING_CAP = 200


def _truncate_lists(obj, string_cap=None):
    if isinstance(obj, list):
        head = [_truncate_lists(x, string_cap) for x in obj[:LIST_CAP]]
        return head + ([f"... <{len(obj) - LIST_CAP} more items truncated>"] if len(obj) > LIST_CAP else [])
    if isinstance(obj, dict):
        if string_cap and _is_uniform_map(obj):  # a list in disguise, e.g. per-module permissions
            keep = list(obj.items())[:LIST_CAP]
            out = {k: _truncate_lists(v, string_cap) for k, v in keep}
            out["..."] = f"<{len(obj) - LIST_CAP} more entries truncated>"
            return out
        return {k: _truncate_lists(v, string_cap) for k, v in obj.items()}
    if string_cap and isinstance(obj, str) and len(obj) > string_cap:
        return obj[:string_cap] + f"... <{len(obj) - string_cap} more characters>"
    return obj


def _is_uniform_map(obj: dict) -> bool:
    """More than 8 keys, every value a dict with the same keys."""
    if len(obj) <= 8:
        return False
    shapes = {tuple(sorted(v)) if isinstance(v, dict) else None for v in obj.values()}
    return len(shapes) == 1 and None not in shapes


def _trim_examples(spec: dict) -> None:
    """Apply the example caps to every operation's examples. Request examples
    keep their strings whole so they stay copy-pasteable."""
    for item in spec["paths"].values():
        for method, op in item.items():
            if method not in ("get", "put", "post", "patch", "delete"):
                continue
            bodies = [((op.get("requestBody") or {}).get("content") or {}, None)]
            bodies += [(r.get("content") or {}, STRING_CAP) for r in op.get("responses", {}).values()]
            for content, cap in bodies:
                for media in content.values():
                    if "example" in media:
                        media["example"] = _truncate_lists(media["example"], cap)
                    for ex in (media.get("examples") or {}).values():
                        if isinstance(ex, dict) and "value" in ex:
                            ex["value"] = _truncate_lists(ex["value"], cap)


def _apply_live_observations(spec: dict) -> int:
    """Overlay captured live request/response bodies onto matching ops.

    Reads `build/live_observations.json` (written by `src/live_test.py`) and
    uses the body from a 2xx run, JWT preferred. Says nothing about which
    credentials an op accepts - that is `_apply_auth_support`'s job.
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
        op = paths.get(template, {}).get(method.lower())
        if not op:
            continue
        successful = {m: r for m, r in (rec.get("by_auth") or {}).items()
                      if r.get("response_status") and 200 <= r["response_status"] < 300}
        if not successful:
            continue
        src = successful["jwt"] if "jwt" in successful else next(iter(successful.values()))
        if src.get("request_body") is not None:
            rb_content = op.setdefault("requestBody", {}).setdefault("content", {})
            # Only overlay onto application/json when the op actually declares
            # it: creating the key on multipart-only routes (file uploads) leaves
            # an empty content entry that renders as `application/json: null`.
            # JSON routes with no declared body still get the captured example.
            if "application/json" in rb_content:
                rb_content["application/json"]["example"] = src["request_body"]
            elif "multipart/form-data" not in rb_content:
                rb_content.setdefault("application/json", {})["example"] = src["request_body"]
        if src.get("response_body") is not None:
            resp = op.setdefault("responses", {}).setdefault(str(src["response_status"]), {"description": "Live-captured response."})
            resp.setdefault("content", {}).setdefault("application/json", {})["example"] = _truncate_lists(src["response_body"])
        op["x-live-captured"] = True
        applied += 1
    return applied


AUTH_PROBE_DIR = OUT.parent / "auth_probe"


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


_AUTH_SCHEMES = {"apikey": "apiKeyAuth", "jwt": "bearerJwt"}


# Pill colors. web/index.html strikes through a pill drawn in the "no" color,
# matching on this exact value, so change both together.
_BADGE_COLOR = {"yes": "#1f8a4c", "no": "#b4372f", "version": "#2f6fde",
                "untested": "#b7791f", "missing": "#6b7280"}


def _auth_badges(by_version: dict[str, dict[str, str]], op: dict) -> list[dict[str, str]]:
    """Scalar ``x-badges`` for one op: a pill per credential (green Yes, red No),
    "Not tested" when no version measured it, "Not found" when the route is
    missing everywhere, and the version that introduced the op when it is newer
    than the oldest version measured. Credential-free ops get none: the empty
    ``security`` already shows it."""
    versions = list(by_version)
    states = {s for v in by_version.values() for s in v.values()}
    badges: list[dict[str, str]] = []

    def pill(name: str, kind: str) -> None:
        badges.append({"name": name, "position": "before", "color": _BADGE_COLOR[kind]})

    if states == {"public"}:
        return badges
    if states <= {"missing", "unreleased"}:
        pill("Not found", "missing")
        return badges
    untested = False
    for mode, label in (("apikey", "API key"), ("jwt", "JWT")):
        measured = [(v, by_version[v][mode]) for v in versions if by_version[v][mode] in ("yes", "no")]
        if not measured:
            untested = True
            continue
        answer = measured[-1][1]
        since = measured[-1][0]
        for v, state in reversed(measured):
            if state != answer:
                break
            since = v
        # Name a version only when an older one answered differently.
        pill(label if since == measured[0][0] else f"{label} ({since}+)", answer)
    if untested:
        pill("Not tested", "untested")
    present = [v for v in versions if not set(by_version[v].values()) <= {"missing", "unreleased"}]
    introduced = op.get("x-fsr-version") or (f"{present[0]}+" if present and present[0] != versions[0] else "")
    if introduced:
        pill(introduced, "version")
    return badges


def _support_on(rec: dict, op: dict, version: str, live: dict) -> dict[str, str]:
    """One box's answer for one op: ``{"apikey": state, "jwt": state}``."""
    needs = (op.get("x-fsr-version") or "").rstrip("+")
    if needs and _version_tuple(needs) > _version_tuple(version):
        # The route does not exist there; its 404 would read as "got past auth".
        return {"apikey": "unreleased", "jwt": "unreleased"}
    if all(rec[m]["verdict"] == "INCONCLUSIVE" and rec[m].get("status") == 404
           and rec[m].get("bogus_status") == 404 for m in ("apikey", "jwt")):
        # 404 to every credential, garbage included: routing answered before auth.
        return {"apikey": "missing", "jwt": "missing"}
    support = {}
    for mode in ("apikey", "jwt"):
        verdict = rec[mode]["verdict"]
        if verdict in ("YES", "PUBLIC", "NO"):
            support[mode] = verdict.lower()
        elif 200 <= ((live.get(mode) or {}).get("response_status") or 0) < 300:
            support[mode] = "yes"
        else:
            support[mode] = "untested"
    return support


def _apply_auth_support(spec: dict) -> int:
    """Stamp each op with a Yes / No per credential, from `build/auth_probe/<version>.json`.

    One file per measured FortiSOAR version. The probe's verdict wins; an op
    the probe could not settle is a Yes only if a live scenario got a 2xx with
    that credential (live captures come from the `.env` box, so only its file
    uses them). An op newer than a box (`x-fsr-version`) is "Not in this
    version" there. The answers become pills (`x-badges`, see `_auth_badges`);
    `security` follows the newest version that has the op.
    """
    boxes = []
    for f in sorted(AUTH_PROBE_DIR.glob("*.json")) if AUTH_PROBE_DIR.exists() else []:
        probe = json.loads(f.read_text())
        boxes.append(((probe.get("fsr_version") or f.stem).split("-")[0], probe))
    if not boxes:
        return 0
    boxes.sort(key=lambda b: _version_tuple(b[0]))
    obs_path = OUT.parent / "live_observations.json"
    obs = json.loads(obs_path.read_text()) if obs_path.exists() else {}
    applied = 0
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            key = f"{method.upper()} {path}"
            live = (obs.get(key) or {}).get("by_auth") or {}
            by_version = {v: _support_on(p["ops"][key], op, v, live if p.get("live_box") else {})
                          for v, p in boxes if key in p.get("ops", {})}
            if not by_version:
                continue
            versions = list(by_version)
            newest = next((by_version[v] for v in reversed(versions)
                           if not set(by_version[v].values()) <= {"missing", "unreleased"}), by_version[versions[-1]])
            op["x-auth"] = newest
            op["x-auth-by-version"] = by_version
            if set(newest.values()) == {"public"}:
                op["security"] = []
            else:
                yes = [_AUTH_SCHEMES[m] for m in ("apikey", "jwt") if newest[m] == "yes"]
                if yes:
                    op["security"] = [{s: []} for s in yes]
            badges = _auth_badges(by_version, op)
            if badges:
                op["x-badges"] = badges
            applied += 1
    return applied


# --- Typed response schemas for platform surfaces (live-verified) ----------
# Wired directly (not via pyfsr response-model tags) where the mapped sample
# is a generic record doctest whose return annotation cannot name the model.
# Shapes come from pyfsr's live-verified models + live_observations.json.
# _apply_typed_response_wiring() runs late in main() because
# `_apply_live_observations` *adds* response codes the hand-written PATH
# entries don't declare (e.g. export_jobs' live 201): wiring before that
# overlay would silently miss them.

def _apply_typed_response_wiring(spec: dict) -> int:
    """Wire direct response $refs for the typed platform surfaces.

    Must run after `_apply_live_observations` (which adds response codes the
    PATH entries don't declare) and may run before or after the pyfsr
    response-model tagger (it never overwrites an existing ``$ref``).
    """
    applied = 0

    def wire(path: str, method: str, code: str, ref, *, collection: bool = False) -> None:
        nonlocal applied
        op = spec["paths"].get(path, {}).get(method)
        if not op:
            return
        resp = (op.get("responses") or {}).get(code)
        if resp is None:
            return
        content = resp.setdefault("content", {}).setdefault("application/json", {})
        if isinstance(ref, dict):
            schema = ref  # inline schema (small shapes not worth a component)
        elif collection:
            schema = {
                "allOf": [
                    {"$ref": "#/components/schemas/HydraCollection"},
                    {"type": "object", "properties": {"hydra:member": {
                        "type": "array",
                        "items": {"$ref": f"#/components/schemas/{ref}"},
                    }}},
                ],
            }
        else:
            schema = {"$ref": f"#/components/schemas/{ref}"}
        content["schema"] = schema
        applied += 1

    def wire_request(path: str, method: str, ref: str) -> None:
        """Point a request body's application/json schema at a component."""
        nonlocal applied
        op = spec["paths"].get(path, {}).get(method)
        if not op:
            return
        rb = (op.get("requestBody") or {}).get("content", {}).get("application/json")
        if rb is None:
            return
        rb["schema"] = {"$ref": f"#/components/schemas/{ref}"}
        applied += 1

    def wire_request_schema(path: str, method: str, schema: dict) -> None:
        """Set an inline request-body schema (open-by-design descriptions)."""
        nonlocal applied
        op = spec["paths"].get(path, {}).get(method)
        if not op:
            return
        rb = (op.get("requestBody") or {}).get("content", {}).get("application/json")
        if rb is None:
            return
        rb["schema"] = schema
        applied += 1

    for _path, _ref in [
        ("/api/3/picklist_names", "PicklistName"),
        ("/api/3/model_metadatas", "ModelMetadata"),
        ("/api/3/staging_model_metadatas", "ModelMetadata"),
        ("/api/3/mcp_configurations", "MCPServerConfig"),
        ("/api/3/llm_activity_logs", "LlmActivityLog"),
        ("/api/auth/config", "AuthConfigRow"),
        ("/api/wf/api/dynamic-variable/", "DynamicVariable"),
    ]:
        wire(_path, "get", "200", _ref, collection=True)
    for _path, _method, _code, _ref in [
        ("/api/3/picklist_names", "post", "201", "PicklistName"),
        ("/api/3/picklist_names/{uuid}", "get", "200", "PicklistName"),
        ("/api/3/picklists", "post", "201", "PicklistItem"),
        ("/api/3/picklists/{uuid}", "get", "200", "PicklistItem"),
        ("/api/3/staging_model_metadatas", "post", "201", "ModelMetadata"),
        ("/api/3/staging_model_metadatas/{uuid}", "get", "200", "ModelMetadata"),
        ("/api/3/staging_model_metadatas/{uuid}", "put", "200", "ModelMetadata"),
        ("/api/3/model_metadatas/{uuid}", "get", "200", "ModelMetadata"),
        ("/api/3/mcp_configurations", "post", "201", "MCPServerConfig"),
        ("/api/3/mcp_configurations/{uuid}", "get", "200", "MCPServerConfig"),
        ("/api/3/mcp_configurations/{uuid}", "put", "200", "MCPServerConfig"),
        ("/api/3/export_jobs", "post", "200", "ExportJob"),
        ("/api/3/export_jobs", "post", "201", "ExportJob"),
        ("/api/3/import_jobs", "post", "200", "ImportJob"),
        ("/api/3/import_jobs", "post", "201", "ImportJob"),
        ("/api/import/{job_uuid}", "get", "200", "ImportJobStatus"),
        ("/api/import/{job_uuid}", "put", "200", "ImportJobStatus"),
        ("/api/integration/data-import/", "get", "200", "IngestionPage"),
        ("/api/integration/data-import/", "post", "201", "IngestionMetadata"),
        ("/api/3/export_templates", "post", "200", "ExportTemplate"),
        ("/api/3/export_templates", "post", "201", "ExportTemplate"),
        ("/api/export", "put", "200", "ExportTriggerResult"),
        ("/api/wf/workflow/config/", "get", "200", "DailyActionCount"),
        ("/api/auth/license", "get", "200", "LicenseInfo"),
        ("/api/auth/cluster/health", "get", "200",
         {"type": "array", "items": {"$ref": "#/components/schemas/ClusterNodeHealth"}}),
        ("/api/public/license", "post", "200", "PublicLicenseResponse"),
        ("/api/version", "get", "200", "VersionInfo"),
        ("/api/product/feature-access", "get", "200", "FeatureAccess"),
        ("/api/permissions/current", "get", "200", "PermissionMap"),
        ("/api/3/actors/current", "get", "200", "CurrentUser"),
        ("/api/gateway/audit/activities", "post", "200", "AuditActivityPage"),
        ("/api/gateway/audit/activities/count", "post", "200", "AuditCount"),
        ("/api/gateway/audit/operations", "get", "200",
         {"type": "array", "items": {"type": "string"},
          "description": "Auditable operation names (e.g. `Create`, `Update`, `Delete`)."}),
        ("/api/auth/config", "put", "200", "AuthConfigWriteResult"),
        ("/api/wf/api/dynamic-variable/", "post", "200", "DynamicVariable"),
        ("/api/views/1/app", "get", "200", "ViewConfig"),
        ("/api/views/1/{name}", "get", "200", "ViewConfig"),
        ("/api/views/1/{name}", "post", "200", "ViewConfig"),
        ("/api/views/1/{name}", "put", "200", "ViewConfig"),
        ("/api/3/changepassword", "put", "200", "MessageResponse"),
        ("/api/wf/api/scheduled/trigger-now/", "post", "200", "MessageResponse"),
        ("/api/wf/api/scheduled/{id}/", "put", "200", "ScheduledTask"),
        ("/api/3/comments/{uuid}", "delete", "200", "Comment"),
        ("/api/publish/revert", "put", "200", "PublishStatus"),
        ("/api/publish/error", "get", "200", "PublishStatus"),
        # Playbook runs
        ("/api/wf/api/historical-steps/", "get", "200", ("HistoricalStep", True)),
        ("/api/wf/api/historical-workflows/", "get", "200", ("WorkflowRun", True)),
        ("/api/wf/api/query/workflow_logs/", "post", "200", ("WorkflowRun", True)),
        ("/api/wf/api/workflows/log_list/", "post", "200", ("WorkflowRun", True)),
        ("/api/wf/api/jinja-editor/", "post", "200", "JinjaRenderResult"),
        ("/api/wf/api/manual-wf-input/{pk}/", "put", "200", "ManualInput"),
        ("/api/wf/api/workflows/count/", "get", "200", "RunCount"),
        ("/api/wf/api/workflows/{pk}/", "get", "200", "WorkflowRun"),
        ("/api/wf/api/workflows/{pk}/approval/", "post", "200", "ApprovalResult"),
        ("/api/wf/api/workflows/{pk}/resume/", "post", "200", "MessageResponse"),
        ("/api/wf/api/workflows/{pk}/retry/", "get", "200", "RetryResult"),
        ("/api/wf/api/workflows/{pk}/start/", "post", "200", "TriggerResponse"),
        # Connectors
        ("/api/3/solutionpacks/install", "post", "200", "ConnectorDefinition"),
        ("/api/integration/agent-heartbeat/{agent}/", "get", "200", "AgentHeartbeat"),
        ("/api/integration/connector/development/entity/{id}/", "post", "200", "ConnectorDefinition"),
        ("/api/integration/connector/development/entity/{id}/files/", "post", "200", "ConnectorFileContent"),
        ("/api/integration/connector/development/entity/{id}/files/", "put", "200", "ConnectorFileTree"),
        ("/api/integration/connector/development/entity/{id}/publish/", "post", "200", "ConnectorDefinition"),
        ("/api/integration/connector_output_schema/{connector}/{version}/", "post", "200", "ConnectorOutputSchema"),
        ("/api/integration/connectors/dependencies_check/{connector}/{version}/", "post", "200", "MessageResponse"),
        ("/api/integration/connectors/{id}/", "post", "200", "ConnectorDefinition"),
        ("/api/integration/install-connector/", "post", "200", "InstallConnectorResult"),
        # MCP gateway / tools (JSON-RPC envelope for the protocol mounts)
        ("/mcp/modules/", "post", "200", "McpJsonRpcResponse"),
        ("/mcp/playbooks/", "post", "200", "McpJsonRpcResponse"),
        ("/mcp/utility/", "post", "200", "McpJsonRpcResponse"),
        ("/mcp/connector/{connector_name}/", "post", "200", "McpJsonRpcResponse"),
        ("/mcp/add/tools", "post", "200", "MCPHostedServer"),
        ("/mcp/add/tools", "post", "201", "MCPHostedServer"),
        ("/mcp/config/export", "post", "200",
         {"type": "array", "items": {"$ref": "#/components/schemas/MCPServerToolsExport"}}),
        ("/mcp/servers/connector", "get", "200", "MCPCandidates"),
        ("/mcp/servers/{mcp_type}", "get", "200", "MCPCandidates"),
        # Records (generic) + misc
        ("/api/3/{collection}", "post", "201", "ModuleRecord"),
        ("/api/3/{collection}/{uuid}", "get", "200", "ModuleRecord"),
        ("/api/3/{collection}/{uuid}", "put", "200", "ModuleRecord"),
        ("/api/3/user_queries", "post", "201", "UserQuery"),
        ("/api/3/routers", "get", "200", ("Router", True)),
        ("/api/triggers/1/notrigger/{workflowId}", "post", "200", "TaskStatusRef"),
        # Captured 2026-10-26 (post-license-recovery run): the dev-workspace
        # round-trip and the AI agent reads.
        ("post", "/api/integration/connector/development/entity/{id}/", "200", "ConnectorDefinition"),
        ("post", "/api/integration/connector/development/entity/{id}/files/", "200", "ConnectorFileContent"),
        ("put", "/api/integration/connector/development/entity/{id}/files/", "200", "ConnectorFileTree"),
        ("post", "/api/integration/connector/development/entity/{id}/publish/", "200", "ConnectorDefinition"),
        ("get", "/api/ai/agent/{uuid}", "200", "AiAgentDTO"),
        ("get", "/api/ai/agent/{name}/{version}/relationships", "200",
         {"type": "array", "items": {"type": "object"},
          "description": "Relationship rows for the agent; `[]` unless relationships are configured."}),
        # JSON-LD machinery (structure is the @context document itself)
        ("/api/3/contexts/{shortName}", "get", "200",
         {"type": "object", "properties": {"@context": {
             "type": "object",
             "description": "JSON-LD context: the module's field-name to IRI/vocabulary mappings.",
         }}, "required": ["@context"]}),
        ("/api/3/docs.jsonld", "get", "200",
         {"type": "object", "properties": {
             "@context": {"description": "Vocabulary mappings."},
             "@id": {"type": "string"},
             "@type": {"type": "string"},
             "hydra:entrypoint": {"type": "string"},
             "hydra:supportedClass": {"type": "array", "items": {"type": "object"},
                                      "description": "One entry per API module: its properties, operations and IRIs."},
         }}),
    ]:
        path_, method_, code_, ref_ = _path, _method, _code, _ref
        collection = False
        if isinstance(ref_, tuple):
            ref_, collection = ref_
        wire(path_, method_, code_, ref_, collection=collection)

    # --- Request bodies (live-verified) -----------------------------------
    for _path, _method, _ref in [
        ("/api/3/mcp_configurations", "post", "MCPServerConfigInput"),
        ("/api/3/mcp_configurations/{uuid}", "put", "MCPServerConfigInput"),
        ("/api/3/roles", "post", "RoleCreate"),
        ("/api/3/teams", "post", "TeamCreate"),
        ("/api/ai/agents/{task_id}/acceptance", "post", "AgentAcceptanceRequest"),
        ("/api/ai/enrich/context", "post", "EnrichContextRequest"),
        ("/api/ai/mcp/validate", "post", "MCPValidateRequest"),
        ("/api/integration/data-import/", "post", "IngestionMetadataInput"),
        ("/api/views/1/{name}", "post", "ViewConfigInput"),
        ("/api/views/1/{name}", "put", "ViewConfigInput"),
        ("/mcp/add/tools", "post", "MCPHostRequest"),
        ("/mcp/tools/{mcp_config_uuid}", "put", "MCPToolsUpdateRequest"),
        ("/mcp/tools/{uuid}", "put", "MCPToolsUpdateRequest"),
        ("/mcp/config/export", "post", "MCPExportRequest"),
    ]:
        wire_request(_path, _method, _ref)

    # --- Request bodies that are open by design (honest descriptions) -----
    # These routes take arbitrary JSON or no body at all; no schema can be
    # more specific without inventing structure the wire doesn't enforce.
    for _path, _method, _schema in [
        ("/api/3/upsert/{moduleType}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "The record's fields, keyed by the module's field names "
                         "(picklist fields take option IRIs). See "
                         "`GET /api/3/contexts/{moduleType}` for the field list."}),
        ("/api/3/{collection}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Fields for the new `{collection}` record, keyed by the "
                         "module's field names (picklist fields take option IRIs). "
                         "See `GET /api/3/contexts/{collection}` for the field list."}),
        ("/api/3/{collection}/{uuid}", "put",
         {"type": "object", "additionalProperties": True,
          "description": "Fields to update (a partial record is accepted)."}),
        ("/api/wf/api/workflows/{pk}/start/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required (live-verified with `{}`). An optional "
                         "JSON payload is accepted and exposed to the run's steps."}),
        ("/api/wf/api/workflows/{pk}/resume/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required on this legacy route (live-verified with "
                          "`{}`); pyfsr resumes paused runs via the manual-input "
                          "routes (`POST /api/wf/api/manual-wf-input/{pk}/retrieve_wfinput/`)."}),
        ("/api/wf/api/workflows/log_list/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Query filters as JSON; `{}` returns every run (live-verified)."}),
        ("/api/wf/api/manual-wf-input/list_wfinput/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Query filters as JSON; `{}` returns every pending manual input (live-verified)."}),
        ("/api/wf/api/manual-wf-input/{pk}/retrieve_wfinput/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required (live-verified with `{}`); the response "
                         "carries the manual input's current answer state."}),
        ("/api/triggers/1/deferred/{name}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Arbitrary input payload exposed to the workflow (deprecated route)."}),
        ("/api/triggers/1/{name}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Arbitrary input payload exposed to the workflow as `$(input)`; "
                         "`{}` is accepted for playbooks that take no input."}),
        ("/api/ai/agent/export/{agent_id}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required (live-verified with `{}`): the agent id in the "
                         "path selects what to export."}),
        ("/api/integration/connectors/{connector}/{version}/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required: the connector slug + version in the path "
                         "select the definition (live-verified with `{}`)."}),
        ("/api/integration/connectors/{id}/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required: the connector id in the path selects the "
                         "definition (live-verified with `{}`)."}),
        ("/api/integration/connectors/agents/{name}/{version}/", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required: query params (`format`, `active`) select; "
                         "the response lists per-agent install rows (live-verified with `{}`)."}),
        ("/api/3/logout", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required."}),
        ("/api/publish/revert", "put",
         {"type": "object", "additionalProperties": True,
          "description": "No body required (live-verified with `{}`)."}),
        ("/api/publish", "put",
         {"type": "object", "additionalProperties": True,
          "description": "No body required."}),
        ("/api/ai/enrich/index/build", "post",
         {"type": "object", "additionalProperties": True,
          "description": "No body required (live-verified with `{}`): rebuilds the "
                         "enrichment context index wholesale."}),
        ("/api/triggers/1/notrigger/{workflowId}", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Arbitrary input payload exposed to the workflow as `$(input)`; "
                         "`{}` is accepted for playbooks that take no input."}),
        ("/api/ai/llm/config", "post",
         {"type": "object", "additionalProperties": True,
          "description": "The LLM profile to register (provider, endpoint, credentials, "
                         "model parameters). See `GET /api/ai/llm/config` for the stored "
                         "shape; the appliance keeps credentials write-only."}),
        ("/mcp/config/import", "post",
         {"type": "object", "additionalProperties": True,
          "description": "Server tool sets in the shape `POST /mcp/config/export` "
                         "produces (one `{uuid, tools: [...]}` entry per server)."}),
    ]:
        wire_request_schema(_path, _method, _schema)
    return applied


def main():
    from merge_ai_mcp import merge_ai_mcp
    ai_paths, ai_op_keys = merge_ai_mcp(SPEC)
    print(f"[AI/MCP] merged {ai_paths} AI/MCP paths")

    pyfsr_applied = apply_pyfsr_samples(PATHS)
    # AI/MCP paths are merged after PATHS is built so we need to apply
    # samples to them separately.
    from pyfsr_examples import build_pyfsr_sample
    ai_sampled = 0
    for http_method, path in ai_op_keys:
        try:
            spec_path = path
            sample = build_pyfsr_sample(http_method, spec_path)
            op = SPEC["paths"].get(path, {}).get(http_method)
            if op and "x-codeSamples" not in op:
                op["x-codeSamples"] = [sample]
                ai_sampled += 1
        except (KeyError, ValueError):
            # No sample for this path - skip silently.
            pass
    if ai_sampled:
        print(f"  [AI/MCP] applied {ai_sampled} pyfsr code samples")

    pyfsr_models_applied = apply_pyfsr_response_models(PATHS, SCHEMAS)
    _ensure_examples(SPEC)
    _apply_curated_examples(SPEC)
    _apply_cross_links(SPEC)
    live_applied = _apply_live_observations(SPEC)
    typed_wired = _apply_typed_response_wiring(SPEC)
    auth_applied = _apply_auth_support(SPEC)
    _trim_examples(SPEC)
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
    # The docs page loads the JSON copy: the browser parses it far faster than YAML.
    OUT.with_suffix(".json").write_text(json.dumps(SPEC, separators=(",", ":")) + "\n")
    op_count = sum(1 for path in PATHS.values() for k in path if k in {"get", "post", "put", "delete", "patch"})
    print(f"Wrote {OUT} ({op_count} operations across {len(PATHS)} paths, "
          f"{live_applied} live-captured, {auth_applied} with measured auth, {pyfsr_applied} with a pyfsr sample, "
          f"{pyfsr_models_applied} with a pyfsr response model, {ai_paths} AI/MCP paths)")


if __name__ == "__main__":
    main()
