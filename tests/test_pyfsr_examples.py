"""Every pyfsr code sample must actually run against a (mocked) FortiSOAR.

`src/pyfsr_examples.py` marks entries as "doctest" (auto-extracted, already
proven by pyfsr's own CI) or "manual" (hand-written, needs proof here). This
file mocks a FortiSOAR appliance well enough to execute every sample verbatim
-- the same failure mode this whole mechanism exists to catch (a sample that
imports a name that doesn't exist, or calls a method with the wrong shape)
would show up as a real exception here, not just look plausible on the page.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pyfsr_examples import PYFSR_EXAMPLES, build_pyfsr_sample  # noqa: E402

_ALERT_UUID = "9f0eb603-ac1e-41c3-b47b-444589beed39"
_AGENT_UUID = "6f5e4d3c-2b1a-4c9d-8e7f-1a2b3c4d5e6f"
_APIKEY_UUID = "660e8400-e29b-41d4-a716-446655440008"
_WF_UUID = "c0d3e8a1-7b2f-4a91-b85e-7d2e1f3a4b56"
_FERNET = "gAAAAABkXyQ_fernet_token_placeholder"


def _fake_response(status_code: int, body: bytes) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = body
    return resp


def _fake_request(self, method, url, **kwargs):
    if url.endswith("/auth/authenticate"):
        return _fake_response(200, b'{"token": "fake-token"}')
    if "staging_model_metadatas" in url:
        # No picklist-backed fields -- friendly values pass through untouched.
        return _fake_response(200, b'{"hydra:member": [{"type": "alerts", "attributes": []}]}')
    # --- Scheduled tasks ---
    # resolve_iri (GET /api/3/workflows?name=...)
    if method == "GET" and "/api/3/workflows?" in url:
        return _fake_response(200, json.dumps({
            "hydra:member": [{"uuid": _WF_UUID, "name": "Nightly Recon",
                              "@id": f"/api/3/workflows/{_WF_UUID}"}],
        }).encode())
    # trigger-now (POST .../scheduled/trigger-now/?...) -- check before the
    # generic scheduled/ POST since the URL contains the same prefix.
    if method == "POST" and "trigger-now" in url:
        return _fake_response(200, b'{"message": "The associated workflow is successfully triggered"}')
    # list (GET /api/wf/api/scheduled/?...)
    if method == "GET" and "/api/wf/api/scheduled" in url:
        return _fake_response(200, json.dumps({
            "hydra:member": [{"id": _FERNET, "name": "nightly-recon", "enabled": True,
                              "crontab": {"minute": "7", "hour": "2"},
                              "kwargs": {"wf_iri": f"/api/3/workflows/{_WF_UUID}"}}],
        }).encode())
    # create (POST /api/wf/api/scheduled/?...)
    if method == "POST" and "/api/wf/api/scheduled/" in url:
        return _fake_response(201, json.dumps({
            "id": _FERNET, "name": "nightly-recon", "enabled": True,
            "task": "workflow.tasks.periodic_task",
            "crontab": {"id": 42, "minute": "7", "hour": "2", "day_of_week": "*",
                        "day_of_month": "*", "month_of_year": "*", "timezone": "UTC"},
            "kwargs": {"wf_iri": f"/api/3/workflows/{_WF_UUID}",
                       "exit_if_running": True, "timezone": "UTC"},
            "schedule_id": 7,
        }).encode())
    # delete (DELETE /api/wf/api/scheduled/{id}/?...)
    if method == "DELETE" and "/api/wf/api/scheduled/" in url:
        return _fake_response(204, b"")
    # --- Notifications ---
    # list (POST .../notifications/?...)
    if method == "POST" and "/api/rule/api/system-notification/notifications" in url:
        return _fake_response(200, json.dumps({
            "hydra:member": [
                {"uuid": "n1", "content": "<p>Task assigned.</p>",
                 "entity_type": "tasks", "read": False},
                {"uuid": "n2", "content": "<p>Approval requested.</p>",
                 "entity_type": "approvals", "read": True},
            ],
            "hydra:totalItems": 2,
        }).encode())
    # purge (POST .../purge/?...)
    if method == "POST" and "/api/rule/api/system-notification/purge" in url:
        return _fake_response(200, b'{"result": "System Notification purge started", "status": "started"}')
    # --- Generic record ops (RecordSet) ---
    # list (GET /api/3/<module>?$limit=...&$page=...) — the paged collection.
    # requests passes params in kwargs, so the URL is the bare collection path.
    # Match before the by-uuid GET; use endswith to exclude /<uuid> suffixes.
    if method == "GET" and url.endswith("/api/3/alerts"):
        return _fake_response(200, json.dumps({
            "@context": "/api/3/contexts/Alert",
            "@id": "/api/3/alerts",
            "hydra:member": [
                {"@id": f"/api/3/alerts/{_ALERT_UUID}", "uuid": _ALERT_UUID,
                 "name": "Response Capture Test Alert", "severity": "High"},
            ],
            "hydra:totalItems": 1,
        }).encode())
    # comments (GET /api/3/<module>/<uuid>/comments?...)
    if method == "GET" and "/comments" in url:
        return _fake_response(200, json.dumps({
            "hydra:member": [{"comment": "Investigating this alert.", "uuid": "c1"}],
            "hydra:totalItems": 1,
        }).encode())
    # upsert (POST /api/3/upsert/<module>) — after picklist resolution
    if method == "POST" and "/api/3/upsert/" in url:
        return _fake_response(200, json.dumps({
            "@id": f"/api/3/alerts/{_ALERT_UUID}", "uuid": _ALERT_UUID,
            "name": "Response Capture Test Alert",
        }).encode())
    # bulk_upsert (POST /api/3/bulkupsert/<module>) — multi-status envelope
    if method == "POST" and "/api/3/bulkupsert/" in url:
        return _fake_response(200, json.dumps({
            "success": [{"name": "pyfsr-bulk-doctest-ok"}],
            "failure": ["row 1: duplicate key"],
        }).encode())
    # bulk_insert (POST /api/3/insert/<module>) — all-succeeded bare collection
    if method == "POST" and "/api/3/insert/" in url:
        return _fake_response(201, json.dumps({
            "@context": "/api/3/contexts/Alert",
            "@id": "/api/3/alerts",
            "hydra:member": [{"name": "Response Capture Test Alert"}],
        }).encode())
    # --- Alerts (existing) ---
    if method == "POST" and url.endswith("/api/3/alerts"):
        return _fake_response(
            201,
            (
                '{"@id": "/api/3/alerts/%s", "uuid": "%s", '
                '"name": "Suspicious Activity", "severity": "High"}' % (_ALERT_UUID, _ALERT_UUID)
            ).encode(),
        )
    if method == "GET" and url.endswith(_ALERT_UUID):
        return _fake_response(
            200,
            (
                '{"@type": "Alert", "@id": "/api/3/alerts/%s", "uuid": "%s", '
                '"name": "Response Capture Test Alert", "severity": "High"}' % (_ALERT_UUID, _ALERT_UUID)
            ).encode(),
        )
    if method == "PUT" and url.endswith(_ALERT_UUID):
        return _fake_response(
            200,
            ('{"@id": "/api/3/alerts/%s", "uuid": "%s", "severity": "Critical"}' % (_ALERT_UUID, _ALERT_UUID)).encode(),
        )
    if method == "DELETE" and url.endswith(_ALERT_UUID):
        return _fake_response(204, b"")
    # --- Typed wrappers: system, alerts, comments, routers, roles, teams ---
    # system.version (GET /api/version)
    if method == "GET" and url.endswith("/api/version"):
        return _fake_response(200, json.dumps({"version": "8.0.0-6034"}).encode())
    # system.permissions (GET /api/permissions/current)
    if method == "GET" and url.endswith("/api/permissions/current"):
        return _fake_response(200, json.dumps(
            {"alerts": {"read": True}, "people": {"create": False}}
        ).encode())
    # system.feature_access (GET /api/product/feature-access)
    if method == "GET" and url.endswith("/api/product/feature-access"):
        return _fake_response(200, json.dumps(
            {"automation": True, "endpoint_management": False}
        ).encode())
    # model_metadatas (GET /api/3/model_metadatas — NOT staging_model_metadatas)
    if method == "GET" and "/api/3/model_metadatas" in url and "staging" not in url:
        return _fake_response(200, json.dumps({"hydra:member": [
            {"type": "threat_intel_feeds",
             "@id": "/api/3/model_metadatas/acbac353-3593-41d2-af46-67951cfab083"},
        ]}).encode())
    # routers.list (GET /api/3/routers) — doctest expects len == 0
    if method == "GET" and url.endswith("/api/3/routers"):
        return _fake_response(200, json.dumps({"hydra:member": []}).encode())
    # roles.list (GET /api/3/roles)
    if method == "GET" and url.endswith("/api/3/roles"):
        return _fake_response(200, json.dumps({"hydra:member": [
            {"name": "Agentic AI", "uuid": "r1", "@id": "/api/3/roles/r1"},
            {"name": "SOC Analyst", "uuid": "r2", "@id": "/api/3/roles/r2"},
            {"name": "Full App Permissions", "uuid": "r3", "@id": "/api/3/roles/r3"},
        ]}).encode())
    # teams.list (GET /api/3/teams)
    if method == "GET" and url.endswith("/api/3/teams"):
        return _fake_response(200, json.dumps({"hydra:member": [
            {"name": "SOC Team", "uuid": "t1", "@id": "/api/3/teams/t1"},
        ]}).encode())
    # comments.list (GET /api/3/comments)
    if method == "GET" and url.endswith("/api/3/comments"):
        return _fake_response(200, json.dumps({
            "hydra:member": [{"comment": "c1", "uuid": "c1"}, {"comment": "c2", "uuid": "c2"}],
            "hydra:totalItems": 2,
        }).encode())
    # --- Agents ---
    if method == "GET" and url.endswith("/api/3/agents"):
        return _fake_response(200, json.dumps({"hydra:member": [
            {"agentId": "edge-1", "name": "edge-1", "uuid": _AGENT_UUID,
             "active": True, "@id": f"/api/3/agents/{_AGENT_UUID}"},
        ]}).encode())
    if method == "GET" and url.endswith(f"/api/3/agents/{_AGENT_UUID}"):
        return _fake_response(200, json.dumps({
            "agentId": "edge-1", "name": "edge-1", "uuid": _AGENT_UUID,
            "active": True, "@id": f"/api/3/agents/{_AGENT_UUID}",
        }).encode())
    if method == "POST" and url.endswith("/api/3/agents"):
        return _fake_response(201, json.dumps({
            "agentId": "edge-1", "name": "edge-1", "uuid": _AGENT_UUID,
            "@id": f"/api/3/agents/{_AGENT_UUID}",
        }).encode())
    if method == "DELETE" and url.endswith(f"/api/3/agents/{_AGENT_UUID}"):
        return _fake_response(204, b"")
    # agents.heartbeat (GET /api/integration/agent-heartbeat/{agent}/)
    if method == "GET" and "/api/integration/agent-heartbeat/" in url:
        return _fake_response(200, json.dumps({"status": "alive"}).encode())
    # agents.installer (POST /api/integration/agent-installer/) — returns bytes
    if method == "POST" and "/api/integration/agent-installer/" in url:
        return _fake_response(200, b"\x1f\x8b\x08\x00binary-installer-blob")
    # agents install/upgrade/uninstall connector (POST/PUT/DELETE install-connector)
    if method in {"POST", "PUT", "DELETE"} and "/api/integration/install-connector/" in url:
        return _fake_response(200, json.dumps({"result": "Success"}).encode())
    # --- API keys ---
    if method == "GET" and url.endswith("/api/3/api_keys"):
        return _fake_response(200, json.dumps({"hydra:member": [
            {"name": "api-key-demo", "uuid": _APIKEY_UUID,
             "userId": "550e8400-e29b-41d4-a716-446655440007",
             "@id": f"/api/3/api_keys/{_APIKEY_UUID}"},
        ]}).encode())
    if method == "GET" and url.endswith(f"/api/3/api_keys/{_APIKEY_UUID}"):
        return _fake_response(200, json.dumps({
            "name": "api-key-demo", "uuid": _APIKEY_UUID,
            "userId": "550e8400-e29b-41d4-a716-446655440007",
            "@id": f"/api/3/api_keys/{_APIKEY_UUID}",
        }).encode())
    if method == "POST" and url.endswith("/api/3/api_keys"):
        return _fake_response(201, json.dumps({
            "name": "test-key", "uuid": _APIKEY_UUID,
            "userId": "550e8400-e29b-41d4-a716-446655440007",
            "@id": f"/api/3/api_keys/{_APIKEY_UUID}",
        }).encode())
    if method == "PUT" and url.endswith(f"/api/3/api_keys/{_APIKEY_UUID}"):
        return _fake_response(200, json.dumps({
            "name": "updated-key", "uuid": _APIKEY_UUID,
            "@id": f"/api/3/api_keys/{_APIKEY_UUID}",
        }).encode())
    # --- Solution packs / import jobs ---
    # POST /api/3/solutionpacks/install serves three callers: by-name
    # SolutionPack install (SolutionPackAPI.install, no $type), multipart
    # connector .tgz upload (ConnectorsAPI.install_from_file, $type=connector),
    # and multipart widget .tgz upload (WidgetsAPI.upload, $type=widget). The
    # connector upload returns a connector-shaped record (integer id + name);
    # the by-name SP install returns a SolutionPack record. Disambiguate by the
    # $type query param so each sample sees the shape its doctest asserts.
    if method == "POST" and url.endswith("/api/3/solutionpacks/install"):
        params = kwargs.get("params") or {}
        type_ = params.get("$type")
        if type_ == "connector":
            return _fake_response(200, json.dumps({
                "name": "demo-connector", "version": "1.0.0",
                "type": "connector", "installed": True,
                "importJob": {"uuid": "420e8400-e29b-41d4-a716-446655440042",
                              "status": "import in progress"},
                "id": 42,
            }).encode())
        return _fake_response(200, json.dumps({
            "name": "SOAR Framework", "version": "2.2.1",
            "job_id": "990e8400-e29b-41d4-a716-446655440012",
            "uuid": "990e8400-e29b-41d4-a716-446655440012",
        }).encode())
    if method == "POST" and url.endswith("/api/3/import_jobs"):
        return _fake_response(201, json.dumps({
            "uuid": "aa0e8400-e29b-41d4-a716-446655440013",
            "@id": "/api/3/import_jobs/aa0e8400-e29b-41d4-a716-446655440013",
            "status": "InProgress",
        }).encode())
    # --- Search ---
    if method == "POST" and url.endswith("/api/search"):
        return _fake_response(200, json.dumps({"hits": {
            "total": 1,
            "hits": [{"_source": {"severity": "Low"}}],
        }}).encode())
    # run_persisted (POST /api/query/{collection}/{queryId}) — BEFORE workflow_logs
    if method == "POST" and "/api/query/" in url and "/api/3/" not in url and "workflow_logs" not in url:
        return _fake_response(200, json.dumps({"hydra:totalItems": 1, "hydra:member": []}).encode())
    # --- Feeds (trigger-bypassing bulk ingest) ---
    if method == "POST" and "/api/ingest-feeds/" in url:
        return _fake_response(200, json.dumps({"status": "success", "uuids": ["u1", "u2"]}).encode())
    # --- TAXII ---
    if method == "GET" and url.endswith("/api/taxii/1/"):
        return _fake_response(200, json.dumps({
            "title": "FortiSOAR TAXII Server", "max_content_length": 10485760,
        }).encode())
    if method == "GET" and url.endswith("/api/taxii/1/collections"):
        return _fake_response(200, json.dumps({"collections": [
            {"id": "malware-samples", "can_read": True, "title": "Malware Samples"},
            {"id": "threat-actors", "can_read": True, "title": "Threat Actors"},
        ]}).encode())
    if method == "GET" and "/api/taxii/1/collections/" in url:
        if "/manifest" in url:
            return _fake_response(200, json.dumps({"objects": [
                {"media_type": "application/stix+json;version=2.1"},
            ]}).encode())
        if "/objects/" in url and url.rstrip("/").split("/")[-1] != "objects":
            return _fake_response(200, json.dumps({"totalItems": 1, "objects": [
                {"name": "example-malware"},
            ]}).encode())
        if "/objects" in url:
            return _fake_response(200, json.dumps({"totalItems": 1, "objects": [
                {"type": "malware"},
            ]}).encode())
        # single collection
        return _fake_response(200, json.dumps({"title": "Malware Samples"}).encode())
    # --- Audit ---
    if method == "POST" and url.endswith("/api/gateway/audit/activities/count"):
        return _fake_response(200, json.dumps({"count": 42}).encode())
    if method == "POST" and url.endswith("/api/gateway/audit/activities"):
        return _fake_response(200, json.dumps({"content": [
            {"user": "admin", "operation": "create", "component": "alerts"},
        ]}).encode())
    if method == "GET" and "/api/gateway/audit/activities/" in url and "operations" not in url:
        return _fake_response(200, json.dumps({
            "operation": "create", "component": "alerts",
        }).encode())
    if method == "GET" and url.endswith("/api/gateway/audit/operations"):
        return _fake_response(200, json.dumps(["login", "create", "update", "delete"]).encode())
    if method == "DELETE" and "/api/gateway/audit/activities/ttl" in url:
        return _fake_response(204, b"")
    # --- Connectors (lifecycle + execute) ---
    # list_configured() / resolve_version() / resolve_connector_id() back onto
    # GET /api/integration/connectors/. The fixture set (smtp, code-snippet,
    # mitre-attack, virustotal) matches pyfsr's replay fixture so the same
    # connector names resolve in both CIs.
    # Healthcheck GET must be matched BEFORE the bare connectors list since
    # both contain "/api/integration/connectors/".
    if method == "GET" and "/api/integration/connectors/healthcheck/" in url:
        return _fake_response(200, json.dumps({
            "status": "Available", "name": "mitre-attack", "version": "2.0.2",
            "message": "Connector is available",
        }).encode())
    if method == "GET" and "/api/integration/connectors/" in url:
        return _fake_response(200, json.dumps({
            "data": [
                {"name": "smtp", "label": "SMTP", "version": "2.6.0", "id": 3,
                 "configurations": [{"config_id": "c3", "name": "Demo", "default": True}]},
                {"name": "code-snippet", "label": "Code Snippet", "version": "2.2.1", "id": 5,
                 "configurations": [{"config_id": "c5", "name": "Demo", "default": True}]},
                {"name": "mitre-attack", "label": "MITRE ATT&CK", "version": "2.0.2", "id": 21,
                 "configurations": [{"config_id": "c21", "name": "Demo", "default": True}]},
                {"name": "virustotal", "label": "VirusTotal", "version": "3.2.1", "id": 16,
                 "configurations": []},
                {"name": "cisa-advisory", "label": "CISA Advisory",
                 "version": "1.0.0", "id": 1,
                 "configurations": [{"config_id": "cfg1", "name": "default", "default": True}]},
            ],
            "totalItems": 5,
        }).encode())
    # connector_detail: POST /api/integration/connectors/<id>/ (the POST-{}
    # operations-discovery quirk). Returns the connector record with operations[].
    if method == "POST" and "/api/integration/connectors/" in url:
        return _fake_response(200, json.dumps({
            "name": "smtp", "version": "2.6.0",
            "operations": [
                {"operation": "send_email_new", "title": "Send Email (Advanced)"},
                {"operation": "send_email", "title": "Send Email"},
            ],
            "configuration": [{"config_id": "c3", "name": "localhost-postfix", "default": True}],
        }).encode())
    # uninstall: DELETE /api/integration/connectors/<id>/ returns 204.
    if method == "DELETE" and "/api/integration/connectors/" in url:
        return _fake_response(204, b"")
    # list_configurations: GET /api/integration/configuration/ (the dedicated,
    # filterable configurations endpoint). Returns the {status, totalItems, data[]}
    # envelope matching pyfsr's replay fixture.
    if method == "GET" and "/api/integration/configuration/" in url:
        return _fake_response(200, json.dumps({
            "status": "success", "totalItems": 2,
            "data": [
                {"id": 1, "config_id": "88c3d39c-2fa9-4731-b00d-29815008f17c",
                 "name": "localhost-postfix", "default": True, "status": 1,
                 "connector": 3, "config": {}},
                {"id": 7, "config_id": "01e4e6b4-c34e-4fc1-b692-bb08591f1fe5",
                 "name": "Demo", "default": True, "status": 1,
                 "connector": 21, "config": {}},
            ],
        }).encode())
    if method == "POST" and "/api/integration/execute/" in url:
        return _fake_response(200, json.dumps({
            "status": "Success",
            "data": {"title": "CISA Advisory", "vulnerabilities": [{"cveID": "CVE-2024-1234"}]},
        }).encode())
    # --- Playbooks ---
    if method == "GET" and url.endswith("/api/wf/api/workflows/count/"):
        return _fake_response(200, json.dumps({"count": 42}).encode())
    # Distinguish workflows/{pk}/ (single run) from workflows/ (collection)
    # using the parsed path segments, not the raw URL.
    _wf_path = urlparse(url).path
    if method == "GET" and _wf_path == "/api/wf/api/workflows/":
        return _fake_response(200, json.dumps({"hydra:member": [
            {"status": "finished", "task_id": "1", "pk": "1",
             "@id": "/api/wf/api/workflows/1/",
             "uuid": "a0afba58-9dbe-44dd-a6e6-7227e33990db"},
        ]}).encode())
    if method == "GET" and _wf_path.startswith("/api/wf/api/workflows/") and _wf_path != "/api/wf/api/workflows/":
        # Single run by pk — 404 on live to fall back to historical
        return _fake_response(404, json.dumps({"detail": "Not found"}).encode())
    if method == "GET" and _wf_path == "/api/wf/api/historical-workflows/":
        return _fake_response(200, json.dumps({"hydra:member": []}).encode())
    if method == "GET" and _wf_path.startswith("/api/wf/api/historical-workflows/") and _wf_path != "/api/wf/api/historical-workflows/":
        return _fake_response(200, json.dumps({
            "status": "finished", "task_id": "1",
            "@id": "/api/wf/api/historical-workflows/1/",
            "uuid": "a0afba58-9dbe-44dd-a6e6-7227e33990db",
        }).encode())
    if method == "POST" and "/api/wf/api/workflows/" in url:
        if "/start/" in url or "/retry/" in url:
            return _fake_response(200, json.dumps({"status": "queued"}).encode())
        if "/log_list/" in url:
            return _fake_response(200, json.dumps({"hydra:member": [
                {"status": "running", "@id": "/api/wf/api/workflows/1/"},
            ]}).encode())
    if method == "POST" and "/api/wf/api/query/workflow_logs/" in url:
        return _fake_response(200, json.dumps({"hydra:member": [
            {"status": "finished", "@id": "/api/wf/api/workflows/1/"},
        ]}).encode())
    if method == "POST" and "/api/wf/api/jinja-editor/" in url:
        return _fake_response(200, json.dumps({"result": "Hello World"}).encode())
    if method == "POST" and "/api/triggers/1/" in url:
        return _fake_response(200, json.dumps({"task_id": "42"}).encode())
    # --- Manual input ---
    if method == "POST" and "/api/wf/api/manual-wf-input/list_wfinput/" in url:
        return _fake_response(200, json.dumps({
            "hydra:member": [{"id": 1, "title": "Enter a six digit number",
                              "is_approval": False, "step_id": 100,
                              "workflow": "encrypted-token"}],
            "hydra:totalItems": 1,
        }).encode())
    if method == "POST" and "/retrieve_wfinput/" in url:
        return _fake_response(200, json.dumps({
            "id": 1, "title": "Enter a six digit number",
            "is_approval": False, "step_id": 100, "workflow": 1,
            "input": {"schema": {"title": "Enter a six digit number",
                                  "inputVariables": [{"name": "num", "type": "number"}]}},
            "response_mapping": {"options": [
                {"option": "Submit", "step_iri": "/api/wf/api/workflows/1/steps/100", "primary": True},
            ]},
        }).encode())
    if method == "POST" and "/wfinput_resume/" in url:
        return _fake_response(200, json.dumps({
            "task_id": "1", "message": "Awaiting Playbook resumed successfully.",
        }).encode())
    raise AssertionError(f"unmocked request: {method} {url}")


def _is_uuid_like(s: str) -> bool:
    """True if ``s`` looks like a uuid (used to distinguish /{pk}/ from collection paths)."""
    return len(s) == 36 and s.count("-") == 4


@pytest.fixture
def mocked_fortisoar():
    with mock.patch("requests.Session.request", _fake_request):
        yield


@pytest.mark.parametrize("key", list(PYFSR_EXAMPLES))
def test_pyfsr_sample_runs(key, mocked_fortisoar):
    """Every entry's rendered source executes cleanly against a mocked appliance."""
    http_method, path = key
    sample = build_pyfsr_sample(http_method, path)
    assert sample["lang"] == "python"
    assert sample["label"] == "pyfsr"
    exec(compile(sample["source"], f"<pyfsr-sample {key}>", "exec"), {})


def test_no_client_class_or_deprecated_auth_form():
    """Regression guard for the 2026-07-13 incident: a hand-written sample
    imported a `Client` class that doesn't exist in pyfsr (real name:
    `FortiSOAR`) and used the deprecated positional `auth=` tuple form."""
    for key in PYFSR_EXAMPLES:
        source = build_pyfsr_sample(*key)["source"]
        assert "import Client" not in source
        assert "from pyfsr import FortiSOAR" in source
        assert "auth=(" not in source
