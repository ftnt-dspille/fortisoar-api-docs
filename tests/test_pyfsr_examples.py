"""Every pyfsr code sample must actually run against a (mocked) FortiSOAR.

`src/pyfsr_examples.py` marks entries as "doctest" (auto-extracted, already
proven by pyfsr's own CI) or "manual" (hand-written, needs proof here). This
file mocks a FortiSOAR appliance well enough to execute every sample verbatim
-- the same failure mode this whole mechanism exists to catch (a sample that
imports a name that doesn't exist, or calls a method with the wrong shape)
would show up as a real exception here, not just look plausible on the page.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pyfsr_examples import PYFSR_EXAMPLES, build_pyfsr_sample  # noqa: E402

_ALERT_UUID = "9f0eb603-ac1e-41c3-b47b-444589beed39"


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
