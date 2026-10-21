"""Probe batch 2: wf run-control, trigger routes, agent/connector ops.

Companion to scripts/probe_lifecycles.py for the playbook/agent clusters.
Safety: trigger runs are fired only against existing, benign playbooks or
records this script created (live-<run>- names); retry targets a run that
already failed on its own; install-connector targets the agent that is
still Awaiting Remote Node Connection so nothing executes on a live VM.

Run:
    python scripts/probe_wf_triggers_agent.py [runs triggers agent]
"""
from __future__ import annotations

import json
import os
import sys
import uuid as _uuid
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

BASE = os.environ["FSR_BASE_URL"].rstrip("/")
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
RUN = _uuid.uuid4().hex[:8]
S = requests.Session()
S.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
S.verify = VERIFY


def login() -> None:
    r = S.post(f"{BASE}/auth/authenticate", verify=VERIFY, timeout=30,
               json={"credentials": {"loginid": os.environ["FSR_USERNAME"],
                                     "password": os.environ["FSR_PASSWORD"]}})
    S.headers["Authorization"] = f"Bearer {r.json()['token']}"


def call(label: str, method: str, path: str, **kw):
    r = S.request(method, f"{BASE}{path}", timeout=60, **kw)
    try:
        body = r.json() if r.content else None
    except ValueError:
        body = f"<non-json {len(r.content)} bytes>"
    print(f"[{label}] {method} {path} -> {r.status_code}")
    print("   ", json.dumps(body)[:400] if body is not None else "(no body)")
    return r.status_code, body


def members(body):
    if isinstance(body, dict):
        return [m for m in (body.get("hydra:member") or body.get("results") or [])
                if isinstance(m, dict)]
    return [m for m in (body or []) if isinstance(m, dict)]


def group_runs() -> None:
    """retry: re-run the newest already-failed playbook run (a normal UI action)."""
    st, runs = call("log_list", "POST", "/api/wf/api/workflows/log_list/",
                    params={"status": "failed", "limit": 5}, json={})
    failed = members(runs)
    if not failed:
        print("[runs] no failed runs found")
        return
    run = failed[0]
    pk = (run.get("@id") or "").rstrip("/").rsplit("/", 1)[-1]
    print(f"[runs] retrying run pk={pk} name={run.get('name')!r} (already failed)")
    call("retry", "POST", f"/api/wf/api/workflows/{pk}/retry/", params={"format": "json"}, json={})


def group_triggers() -> None:
    """notrigger (manual-execute), named webhook, action route — on benign targets."""
    # notrigger: active 2-step manual playbook "Export Records As CSV"
    pb_uuid = _pb_by_name("Export Records As CSV")
    if not pb_uuid:
        print("[triggers] template playbook not found; skipping trigger probes")
        return
    call("notrigger", "POST", f"/api/triggers/1/notrigger/{pb_uuid}", json={})

    # named webhook: the api-endpoint test playbook's route
    route = _trigger_route(_pb_by_name("FortiSOAR Playbook API test 2"))
    if route:
        call("webhook", "POST", f"/api/triggers/1/{route}", json={})
    else:
        print("[triggers] no api-endpoint route found; skipping webhook probe")

    # action route: the manual playbook's trigger route, against OUR record
    r = S.post(f"{BASE}/api/3/alerts", json={"name": f"live-{RUN}-action", "source": "live_test"},
               timeout=30)
    alert_iri = r.json().get("@id")
    print(f"[triggers] our alert: {alert_iri}")
    route = route or _trigger_route(pb_uuid)
    print(f"[triggers] action route uuid: {route}")
    if route and alert_iri:
        call("action", "POST", f"/api/triggers/1/action/{route}",
             json={"singleRecordExecution": True, "__resource": "alerts",
                   "records": [alert_iri], "__uuid": pb_uuid})
    # deferred: expected 404 on 8.0.0 for every name (pyfsr live-verified)
    call("deferred", "POST", "/api/triggers/1/deferred/no-such-route", json={})
    # cleanup our alert
    if alert_iri:
        S.delete(f"{BASE}{alert_iri}", timeout=30)


def _pb_by_name(name: str) -> str | None:
    r = S.get(f"{BASE}/api/3/workflows", params={"name": name, "$limit": 10}, timeout=30)
    return next((m.get("uuid") for m in members(r.json()) if m.get("name") == name), None)


def _trigger_route(pb_uuid: str | None) -> str | None:
    if not pb_uuid:
        return None
    r = S.get(f"{BASE}/api/3/workflows/{pb_uuid}", params={"$relationships": "true"},
              timeout=30)
    ts = (r.json() or {}).get("triggerStep") or {}
    if isinstance(ts, dict):
        return (ts.get("arguments") or {}).get("route")
    return None


def group_agent() -> None:
    """heartbeat (real agentId), installer blob, install/upgrade/uninstall on
    the agent that is still Awaiting Remote Node Connection."""
    r = S.get(f"{BASE}/api/3/agents", params={"$limit": 30}, timeout=30)
    agents = members(r.json())
    # resolve configurationHealth picklist IRIs -> labels
    iris = {a.get("configurationHealth", {}).get("@id") for a in agents
            if isinstance(a.get("configurationHealth"), dict)}
    labels = {}
    if iris:
        rp = S.get(f"{BASE}/api/3/picklists", params={"$limit": 1000}, timeout=30)
        for p in members(rp.json()):
            if p.get("@id") in iris:
                labels[p["@id"]] = p.get("itemValue") or ""
    awaiting = [a for a in agents
                if labels.get((a.get("configurationHealth") or {}).get("@id"))
                == "Awaiting Remote Node Connection"]
    target = awaiting[0] if awaiting else None
    print(f"[agent] awaiting-agent target: {target and target.get('name')}")
    for a in agents[:3]:
        call("heartbeat", "GET", f"/api/integration/agent-heartbeat/{a.get('agentId')}/")
    if not target:
        print("[agent] no awaiting agent; skipping install lifecycle")
        return
    agent_id = target.get("agentId")
    # installer bundle (binary; print size only)
    r = S.post(f"{BASE}/api/integration/agent-installer/", params={"format": "json"},
               json={"agent": agent_id, "connectors": [],
                     "include_last_known_configurations": False}, timeout=120)
    print(f"[installer] -> {r.status_code} ({len(r.content)} bytes, ct={r.headers.get('Content-Type')})")
    # connector catalog lookup for a real name/version pair
    r = S.get(f"{BASE}/api/integration/connectors/", params={"name": "cyops_utilities", "format": "json"},
              timeout=30)
    cat = r.json() if r.content else None
    rows = cat if isinstance(cat, list) else members(cat)
    version = (rows[0] or {}).get("version") if rows else None
    print(f"[agent] catalog cyops_utilities version: {version}")
    if version:
        body = {"name": "cyops_utilities", "label": "cyops_utilities", "version": version,
                "rpm_full_name": "", "category": [], "description": "",
                "publisher": "Fortinet", "agent": [agent_id]}
        call("install", "POST", "/api/integration/install-connector/",
             params={"format": "json"}, json=body)
        call("upgrade", "PUT", "/api/integration/install-connector/",
             params={"format": "json"},
             json={"name": "cyops_utilities", "version": version, "agent_id": agent_id})
        call("uninstall", "DELETE", "/api/integration/install-connector/",
             params={"format": "json"},
             json={"name": "cyops_utilities", "version": version, "agent_id": agent_id})


GROUPS = {"runs": group_runs, "triggers": group_triggers, "agent": group_agent}

if __name__ == "__main__":
    login()
    for name in (sys.argv[1:] or list(GROUPS)):
        print(f"\n===== {name} =====")
        try:
            GROUPS[name]()
        except Exception as exc:
            print(f"[{name}] FAILED: {exc!r}")
