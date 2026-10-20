"""Capture response bodies for documented ops whose 2xx response has none.

The curated spec describes some responses in words only, so Scalar shows
"No Body" for them. This script calls each of those ops on a live appliance
through pyfsr, scrubs the body (same scrubbers as live_test.py), and merges it
into build/live_observations.json, where build_curated.py picks it up as the
response example.

Writes only touch throwaway objects named ``live-capture-<run>`` and remove
them again; the dev-workspace publish republishes a connector's own unchanged
code.

    .venv/bin/python src/capture_bodies.py              # every capture
    .venv/bin/python src/capture_bodies.py views users  # only these groups
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from pyfsr import FortiSOAR

from live_test import OBSERVATIONS_PATH, _scrub
from sanitize import scrub_value

ROOT = Path(__file__).resolve().parent.parent
RUN = secrets.token_hex(4)
PREFIX = f"live-capture-{RUN}"

# A small, non-system connector to configure, open in the Studio and republish.
# Republishing gives it a new integer id, so look the id up each run.
CONNECTOR = "ipstack"

GROUPS: dict[str, Callable[["Capture"], None]] = {}


def group(fn: Callable[["Capture"], None]) -> Callable[["Capture"], None]:
    GROUPS[fn.__name__] = fn
    return fn


class Capture:
    def __init__(self, client: FortiSOAR) -> None:
        self.client = client
        self.observations: dict[str, dict] = {}
        self.cleanup: list[tuple[str, Callable[[], Any]]] = []

    def call(self, method: str, template: str, path: str | None = None, data: Any = None,
             params: dict | None = None, record: bool = True) -> tuple[int, Any]:
        """Send through pyfsr and, on a 2xx, record the body under ``METHOD template``."""
        r = self.client.request(method, path or template, params=params, data=data, raise_on_status=False)
        try:
            body = r.json() if r.content else None
        except ValueError:
            body = None
        print(f"  {method} {path or template} -> {r.status_code}"
              + ("" if r.status_code < 400 else f" {r.text[:200]}"), flush=True)
        if record and 200 <= r.status_code < 300:
            self.observations[f"{method} {template}"] = {"by_auth": {"jwt": {
                "request_body": _clean(data),
                "response_status": r.status_code,
                "response_body": _clean(body),
            }}}
        return r.status_code, body

    def later(self, label: str, fn: Callable[[], Any]) -> None:
        self.cleanup.append((label, fn))


def _clean(value: Any) -> Any:
    return None if value is None else _trim(scrub_value(_scrub(value)))


def _trim(value: Any) -> Any:
    """Keep two items of any list and the head of any long string: the docs
    need the shape, and some bodies (connector sample data) run to megabytes."""
    if isinstance(value, list):
        return [_trim(v) for v in value[:2]] + ([f"... <{len(value) - 2} more>"] if len(value) > 2 else [])
    if isinstance(value, dict):
        return {k: _trim(v) for k, v in value.items()}
    if isinstance(value, str):
        value = _ISO_TIME.sub("2024-01-01T00:00:00Z", value)
        return value[:300] + "..." if len(value) > 300 else value
    return value


# Server timestamps would date the capture; docs only need the format.
_ISO_TIME = re.compile(r"\b20\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?")


def _members(body: Any) -> list[dict]:
    if isinstance(body, dict):
        return body.get("hydra:member") or body.get("data") or []
    return body if isinstance(body, list) else []


@group
def connectors(cap: Capture) -> None:
    c = cap.client
    version = c.connectors.connector_detail(CONNECTOR)["version"]
    cv = f"{CONNECTOR}/{version}"
    cap.call("POST", "/api/integration/connectors/{connector}/{version}/",
                             f"/api/integration/connectors/{cv}/", data={}, params={"format": "json"})
    # ipstack's schema is static (in the definition above); this endpoint
    # infers one by running the op, so use a local Utilities op.
    cap.call("POST", "/api/integration/connector_output_schema/{connector}/{version}/",
             "/api/integration/connector_output_schema/cyops_utilities/"
             f"{c.connectors.connector_detail('cyops_utilities')['version']}/",
             data={"operation": "ip_cidr_check", "config": "",
                   "params": {"ip": "192.0.2.1", "cidr_range": "192.0.2.0/24"}},
             params={"format": "json"})
    cap.call("GET", "/api/integration/connectors/dependencies_check/{connector}/{version}/",
             f"/api/integration/connectors/dependencies_check/{cv}/")
    cap.call("POST", "/api/integration/connectors/dependencies_check/{connector}/{version}/",
             f"/api/integration/connectors/dependencies_check/{cv}/")
    cap.call("POST", "/api/integration/connector_details/", data={"connector": "mitre-attack"})
    cap.call("GET", "/api/integration/data-import/")


@group
def configuration(cap: Capture) -> None:
    c = cap.client
    cfg = c.connectors.create_configuration(
        CONNECTOR, {"server_url": "https://api.ipstack.example.com", "api_key": "placeholder",
                    "verify_ssl": True}, name=PREFIX, validate=False)
    config_id = cfg.config_id
    cap.later("connector configuration", lambda: c.connectors.delete_configuration(config_id))
    tpl = "/api/integration/configuration/{config_id}/"
    path = f"/api/integration/configuration/{config_id}/"
    _, body = cap.call("GET", tpl, path)
    put = {k: body[k] for k in ("name", "config", "default", "status", "teams", "connector", "agent")
           if k in body}
    put["name"] = f"{PREFIX}-renamed"
    cap.call("PUT", tpl, path, data=put)
    me = c.get("/api/3/actors/current")["uuid"]
    _, meta = cap.call("POST", "/api/integration/data-import/", data={
        "name": PREFIX, "description": f"Metadata for {PREFIX}", "created_by": me, "modified_by": me,
        "owners": [], "connector": {"name": CONNECTOR, "version": body.get("version", "")},
        "configuration": config_id,
        "metadata": {"scheduleId": None, "scheduleName": "", "scheduleStatus": False}})
    if meta and meta.get("id"):
        cap.later("data-import record", lambda: c.delete(f"/api/integration/data-import/{meta['id']}/"))


@group
def agent_install(cap: Capture) -> None:
    """Install, re-install and uninstall the throwaway connector on a remote agent."""
    c = cap.client
    agents = _members(c.get("/api/3/agents", params={"$limit": 50}))
    agent = next((a["agentId"] for a in agents if a.get("active") and not a.get("isLocal")), None)
    if agent is None:
        return
    body = {"name": CONNECTOR, "version": c.connectors.connector_detail(CONNECTOR)["version"],
            "agent_id": agent}
    status, _ = cap.call("POST", "/api/integration/install-connector/", data=body)
    if status < 300:
        cap.later("agent install", lambda: c.request("DELETE", "/api/integration/install-connector/",
                                                    data=body, raise_on_status=False))
    cap.call("PUT", "/api/integration/install-connector/", data=body)
    cap.call("DELETE", "/api/integration/install-connector/", data=body)


@group
def heartbeat(cap: Capture) -> None:
    agents = _members(cap.client.get("/api/3/agents", params={"$limit": 50}))
    live = [a for a in agents if a.get("active") and not a.get("isLocal")]
    if live:
        cap.call("GET", "/api/integration/agent-heartbeat/{agent}/",
                 f"/api/integration/agent-heartbeat/{live[0]['agentId']}/")


@group
def views(cap: Capture) -> None:
    cap.call("GET", "/api/views/1/app")
    cap.call("GET", "/api/views/1/{name}", "/api/views/1/modules-alerts-list")


@group
def workflow(cap: Capture) -> None:
    c = cap.client
    cap.call("GET", "/api/wf/api/dynamic-variable/", params={"limit": 3})
    name = PREFIX.replace("-", "_")
    _, var = cap.call("POST", "/api/wf/api/dynamic-variable/",
                      data={"name": name, "value": "example", "default_value": "example"})
    if var and var.get("id"):
        cap.later("dynamic variable", lambda: c.delete(f"/api/wf/api/dynamic-variable/{var['id']}/"))
    cap.call("GET", "/api/wf/api/manual-wf-input/", params={"limit": 3})
    cap.call("GET", "/api/wf/workflow/config/", params={"section": "license"})
    cap.call("GET", "/api/wf/api/historical-steps/", params={"limit": 1})


@group
def manual_input(cap: Capture) -> None:
    """Start the "E2E - Manual Input" playbook, PUT its pending input, then answer it."""
    c = cap.client
    title = "E2E test gate"
    seen = {mi.id for mi in c.manual_input.list(assigned_to="all")}
    c.playbooks.trigger("E2E - Manual Input")
    pending = None
    for _ in range(45):
        pending = next((mi for mi in c.manual_input.list(assigned_to="all")
                        if mi.id not in seen and mi.title == title), None)
        if pending:
            break
        time.sleep(2)
    if pending is None:
        print("  no pending input appeared")
        return
    cap.later("pending manual input", lambda: c.manual_input.answer(input_id=pending.id))
    record = c.manual_input.retrieve(pending.id)
    current = record.get("input") if isinstance(record, dict) else record.input
    if hasattr(current, "model_dump"):
        current = current.model_dump(mode="json", by_alias=True, exclude_none=True)
    cap.call("PUT", "/api/wf/api/manual-wf-input/{pk}/", f"/api/wf/api/manual-wf-input/{pending.id}/",
             data={"input": current, "workflow": record.get("workflow") if isinstance(record, dict)
                   else record.workflow})


@group
def ingest(cap: Capture) -> None:
    c = cap.client
    value = f"{RUN}.capture.example.com"
    cap.call("POST", "/api/ingest-feeds/{module}", "/api/ingest-feeds/indicators",
             data={"data": [{"value": value}]})
    if "POST /api/ingest-feeds/{module}" in cap.observations:  # same call, both documented paths
        cap.observations["POST /api/ingest-feeds/indicators"] = cap.observations["POST /api/ingest-feeds/{module}"]

    def remove() -> None:
        for hit in _members(c.get("/api/3/indicators", params={"value": value})):
            c.delete(hit["@id"])
    cap.later("ingested indicator", remove)


@group
def staging(cap: Capture) -> None:
    c = cap.client
    slug = PREFIX.replace("-", "_")
    body = {"type": slug, "module": slug, "tableName": slug, "displayName": PREFIX,
            "descriptions": {"singular": PREFIX, "plural": PREFIX}, "ownable": False,
            "taggable": False, "queueable": False, "softDeleteable": False,
            "attributes": [{"name": "name", "type": "string", "formType": "text",
                            "descriptions": {"singular": "Name"}, "visibility": True,
                            "writeable": True, "validation": {"required": False}}]}
    status, created = cap.call("POST", "/api/3/staging_model_metadatas", data=body,
                               params={"$relationships": "true"})
    if status >= 300 or not created:
        return
    uuid = created["uuid"]
    cap.later("staged module", lambda: c.delete(f"/api/3/staging_model_metadatas/{uuid}"))
    cap.call("PUT", "/api/3/staging_model_metadatas/{uuid}", f"/api/3/staging_model_metadatas/{uuid}",
             data={"displayName": f"{PREFIX} renamed"}, params={"$relationships": "true"})


@group
def auth_config(cap: Capture) -> None:
    current = cap.client.auth_config.get("API-KEYS")["retrievable_mode"]
    # write back the value it already has
    cap.call("PUT", "/api/auth/config", data={"option": "retrievable_mode", "value": current})


@group
def users(cap: Capture) -> None:
    c = cap.client
    login = PREFIX.replace("-", "")
    old, new = f"Aa1!{secrets.token_urlsafe(12)}", f"Bb2!{secrets.token_urlsafe(12)}"
    roles = [r.name for r in c.users.list_roles()][:1]
    person = c.users.create(login, old, "Live", "Capture", f"{login}@example.com", roles, typed=False)
    uuid = person.get("uuid") or person["@id"].rsplit("/", 1)[-1]

    def remove() -> None:
        c.users.deactivate(login)
        c.delete(f"/api/3/people/{uuid}")
    cap.later("throwaway user", remove)
    them = FortiSOAR(c.base_url, username=login, password=old, verify_ssl=False,
                     suppress_insecure_warnings=True, max_retries=0, timeout=30)
    me = them.users.whoami()
    sub = Capture(them)
    # A POST or PUT on /api/views/1/{name} saves the caller's own layout, so
    # write it as the throwaway user.
    view = "/api/views/1/modules-alerts-list"
    for method in ("POST", "PUT"):
        # The server only finds a user's own copy when isDefault is true; a
        # copy saved without it is never read back, and the next write 409s.
        _, layout = sub.call("GET", "/api/views/1/{name}", view, record=False)
        keys = ("type", "module", "viewOptions", "isDefault", "config")
        sub.call(method, "/api/views/1/{name}", view, data={k: (layout or {}).get(k) for k in keys})
    sub.call("PUT", "/api/3/changepassword", data={"uuid": me["person_uuid"], "loginId": me["loginid"],
                                                    "oldPassword": old, "newPassword": new})
    cap.observations.update(sub.observations)


@group
def dev_workspace(cap: Capture) -> None:
    c = cap.client
    base = "/api/integration/connector/development/entity"
    installed = c.connectors.connector_detail(CONNECTOR)["id"]
    _, dev = cap.call("POST", base + "/{id}/", f"{base}/{installed}/", data={"edit_repo_connector": True})
    dev_id = (dev or {}).get("id")
    if not dev_id or dev_id == installed:
        print("  no dev twin returned; skipping file + publish captures")
        return
    published = False

    def remove() -> None:
        if not published:
            c.delete(f"{base}/{dev_id}/")
    cap.later("dev-workspace twin", remove)
    info = _find_file(dev, "info.json")
    if info:
        _, read = cap.call("POST", base + "/{id}/files/", f"{base}/{dev_id}/files/", data={"xpath": info})
        content = (read or {}).get("fileContent")
        if content is not None:  # save the file back unchanged
            cap.call("PUT", base + "/{id}/files/", f"{base}/{dev_id}/files/",
                     data={"fileData": {"xpath": info, "fileContent": content}})
    status, _ = cap.call("POST", base + "/{id}/publish/", f"{base}/{dev_id}/publish/",
                         data={"discard": True, "replace": True})
    published = status < 300
    # Publishing recycles the integrations workers; wait until they answer
    # again so later calls (and cleanups) do not hit a 502.
    for _ in range(30):
        if c.request("GET", "/api/integration/connectors/", params={"page_size": 1},
                     raise_on_status=False).status_code == 200:
            break
        time.sleep(2)


def _find_file(node: Any, name: str) -> str | None:
    if isinstance(node, dict):
        for key in ("xpath", "path"):
            if isinstance(node.get(key), str) and node[key].endswith("/" + name):
                return node[key]
        node = list(node.values())
    if isinstance(node, list):
        for item in node:
            hit = _find_file(item, name)
            if hit:
                return hit
    return None


def merge(observations: dict[str, dict]) -> None:
    prior = json.loads(OBSERVATIONS_PATH.read_text()) if OBSERVATIONS_PATH.exists() else {}
    for key, rec in observations.items():
        prior.setdefault(key, {"by_auth": {}}).setdefault("by_auth", {}).update(rec["by_auth"])
    OBSERVATIONS_PATH.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n")


def main() -> int:
    load_dotenv(ROOT / ".env", override=True)
    client = FortiSOAR(os.environ["FSR_BASE_URL"], username=os.environ["FSR_USERNAME"],
                       password=os.environ["FSR_PASSWORD"],
                       verify_ssl=os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true",
                       suppress_insecure_warnings=True, max_retries=0, timeout=60)
    cap = Capture(client)
    wanted = sys.argv[1:] or list(GROUPS)
    try:
        for name in wanted:
            print(f"== {name}", flush=True)
            try:
                GROUPS[name](cap)
            except Exception as e:  # noqa: BLE001 -- one group failing must not skip the rest
                print(f"  FAILED: {type(e).__name__}: {e}"[:400], flush=True)
    finally:
        for label, fn in reversed(cap.cleanup):
            try:
                fn()
                print(f"  cleaned up {label}")
            except Exception as e:  # noqa: BLE001
                print(f"  CLEANUP FAILED for {label}: {type(e).__name__}: {e}"[:300])
    merge(cap.observations)
    print(f"recorded {len(cap.observations)} op(s): " + ", ".join(sorted(cap.observations)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
