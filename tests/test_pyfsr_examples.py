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

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pyfsr_examples import PYFSR_EXAMPLES, build_pyfsr_sample  # noqa: E402

_ALERT_UUID = "9f0eb603-ac1e-41c3-b47b-444589beed39"
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
                '{"@id": "/api/3/alerts/%s", "uuid": "%s", '
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
    raise AssertionError(f"unmocked request: {method} {url}")


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
