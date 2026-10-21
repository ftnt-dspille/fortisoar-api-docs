"""Probe the create/update/delete (API-3 + feeds + schedules) lifecycles for
payload shapes that actually 2xx, printing full response bodies.

This is the payload-discovery step before wiring scenarios into
`src/live_test.py` (whose observation recorder drops non-2xx bodies, so
payload debugging has to happen here).

Safety contract mirrors `src/live_test.py`: everything created is named
`live-<run>-...`, every DELETE body / path references only IRIs this run
created, and `finally` sweeps anything left behind.

Run:
    python scripts/probe_lifecycles.py            # all groups
    python scripts/probe_lifecycles.py module     # just the module CRUD group
    python scripts/probe_lifecycles.py picklists schedules mcp search feeds
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid as _uuid
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

BASE = os.environ["FSR_BASE_URL"].rstrip("/")
KEY = os.environ["FSR_API_KEY"]
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
RUN = _uuid.uuid4().hex[:8]
S = requests.Session()
S.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
S.verify = VERIFY


def login() -> str:
    """JWT preferred: 8.0.0 denies several API-3 writes (picklists) to API keys."""
    user, pw = os.environ.get("FSR_USERNAME", ""), os.environ.get("FSR_PASSWORD", "")
    if user and pw:
        r = S.post(f"{BASE}/auth/authenticate", verify=VERIFY, timeout=30,
                   json={"credentials": {"loginid": user, "password": pw}})
        if r.ok and r.json().get("token"):
            S.headers["Authorization"] = f"Bearer {r.json()['token']}"
            return "jwt"
    if KEY:
        S.headers["Authorization"] = f"API-KEY {KEY}"
        return "apikey"
    raise SystemExit("no working credentials in .env")


def call(label: str, method: str, path: str, **kw) -> tuple[int, dict | list | None]:
    r = S.request(method, f"{BASE}{path}", timeout=30, **kw)
    try:
        body = r.json() if r.content else None
    except ValueError:
        body = r.text[:200] if r.content else None
    print(f"[{label}] {method} {path} -> {r.status_code}")
    print(json.dumps(body, indent=1)[:1200] if body is not None else "(no body)")
    return r.status_code, body


def members(body) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        return body.get("hydra:member") or body.get("content") or []
    return []


def picklist_iri(taxonomy: str, value: str) -> str | None:
    """Resolve one value IRI from a picklist taxonomy (same recipe as bulk_crud)."""
    r = S.get(f"{BASE}/api/3/picklist_names", params={"$limit": 200}, timeout=30)
    for m in members(r.json() if r.ok else {}):
        if m.get("name") == taxonomy:
            pln = m.get("@id", "").rsplit("/", 1)[-1]
            rr = S.get(f"{BASE}/api/3/picklists",
                       params={"listName": pln, "$limit": 50}, timeout=30)
            for v in members(rr.json() if rr.ok else {}):
                if v.get("itemValue") == value:
                    return v.get("@id")
    return None


def verify_gone(label: str, iri: str) -> None:
    r = S.get(f"{BASE}{iri}", timeout=30)
    print(f"[{label}] verify-gone GET {iri} -> {r.status_code} "
          f"{'(gone OK)' if r.status_code == 404 else '(STILL PRESENT!)'}")


def group_module() -> None:
    """insert -> update -> verify -> delete (only our @ids) -> verify gone."""
    sev = picklist_iri("Severity", "High")
    status = picklist_iri("AlertStatus", "Open")
    assert sev and status, f"picklist IRIs not resolved: {sev=} {status=}"
    name = f"live-{RUN}-insert"
    created_iris: list[str] = []

    st, body = call("insert", "POST", "/api/3/insert/alerts", json=[
        {"name": name, "source": "live_test", "sourceId": f"probe-{RUN}",
         "severity": sev, "status": status},
    ])
    rows = body if isinstance(body, list) else (body or {}).get("hydra:member") or []
    created_iris = [r.get("@id") for r in rows if isinstance(r, dict) and r.get("@id")]
    if not created_iris:
        # Maybe the response nests differently; find our record by name instead.
        r = S.get(f"{BASE}/api/3/alerts", params={"$search": name, "$limit": 5}, timeout=30)
        created_iris = [m.get("@id") for m in members(r.json() if r.ok else {})
                        if m.get("name") == name]
    print(f"[insert] created IRIs: {created_iris}")

    if created_iris:
        call("update", "PUT", "/api/3/update/alerts", json=[
            {"@id": iri, "description": f"updated by probe {RUN}"} for iri in created_iris
        ])
        for iri in created_iris:
            r = S.get(f"{BASE}{iri}", timeout=30)
            print(f"[update] verify GET {iri} -> {r.status_code} "
                  f"desc={(r.json() or {}).get('description')!r}"[:160])

    if created_iris:
        call("delete", "DELETE", "/api/3/delete/alerts", json=created_iris)
        for iri in created_iris:
            verify_gone("delete", iri)
    else:
        print("[lifecycle] nothing created; skipping update/delete")


def group_picklists() -> None:
    """Create our own picklist list -> add a value -> delete value -> delete list."""
    list_name = f"live{RUN}ProbeList"  # PascalCase-ish, unique instance-wide
    st, body = call("pln-create", "POST", "/api/3/picklist_names",
                    json={"name": list_name, "system": False})
    pln_iri = (body or {}).get("@id") if isinstance(body, dict) else None
    pln_uuid = pln_iri.rsplit("/", 1)[-1] if pln_iri else None
    if not pln_uuid:
        r = S.get(f"{BASE}/api/3/picklist_names", params={"$search": list_name, "$limit": 5}, timeout=30)
        m = next((m for m in members(r.json() if r.ok else {})
                  if m.get("name") == list_name), None)
        pln_iri, pln_uuid = (m.get("@id"), m.get("uuid") or m.get("@id", "").rsplit("/", 1)[-1]) if m else (None, None)
    print(f"[pln] our list IRI: {pln_iri}")

    val_iri = None
    if pln_iri:
        st, body = call("pl-value", "POST", "/api/3/picklists", json={
            "itemValue": f"live-{RUN}-opt", "listName": pln_iri,
            "color": "#4CAF50", "orderIndex": 1,
        })
        val_iri = body.get("@id") if isinstance(body, dict) else None

    if pln_iri:
        r = S.get(f"{BASE}{pln_iri}", timeout=30)
        print(f"[pln] verify GET -> {r.status_code}")

    for label, iri in (("pl-value-del", val_iri), ("pln-del", pln_iri)):
        if iri:
            call(label, "DELETE", iri)
            verify_gone(label, iri)


def group_mcp() -> None:
    """Mirror an existing mcp_configuration record's shape, then PUT + DELETE ours."""
    r = S.get(f"{BASE}/api/3/mcp_configurations", params={"$limit": 2}, timeout=30)
    sample = next(iter(members(r.json() if r.ok else {})), None)
    if not sample:
        print("[mcp] no existing configuration to mirror; aborting group")
        return
    print("[mcp] sample record keys:", sorted(k for k in sample if not k.startswith("@")))
    name = f"live-{RUN}-mcp"
    body = {k: sample[k] for k in ("config", "connector_name") if k in sample}
    body.setdefault("name", name)
    st, created = call("mcp-create", "POST", "/api/3/mcp_configurations", json=body)
    iri = created.get("@id") if isinstance(created, dict) else None
    if not iri:
        print("[mcp] no @id in response; aborting PUT/DELETE")
        return
    call("mcp-get", "GET", iri)
    call("mcp-update", "PUT", iri, json={**body, "name": f"live-{RUN}-mcp2"})
    call("mcp-delete", "DELETE", iri)
    verify_gone("mcp", iri)


def group_schedules() -> None:
    """Create a disabled schedule on an existing workflow, PUT it, DELETE it."""
    r = S.get(f"{BASE}/api/wf/api/workflows", params={"$limit": 5}, timeout=30)
    wf = next(iter(members(r.json() if r.ok else {})), None)
    if not wf:
        print("[sched] no workflows on appliance; aborting group")
        return
    wf_iri = wf.get("@id") or f"/api/wf/api/workflows/{wf.get('uuid') or wf.get('id')}"
    print(f"[sched] using workflow {wf_iri} ({wf.get('name')})")
    name = f"live-{RUN}-schedule"
    st, created = call("sched-create", "POST", "/api/wf/api/scheduled/", json={
        "name": name,
        "crontab": {"minute": "7", "hour": "3", "day_of_week": "*",
                    "day_of_month": "1", "month_of_year": "1", "timezone": "UTC"},
        "kwargs": {"wf_iri": wf_iri, "exit_if_running": True},
        "enabled": False,  # never let it actually fire
    })
    iri = created.get("@id") if isinstance(created, dict) else None
    if not iri:
        r = S.get(f"{BASE}/api/wf/api/scheduled/", params={"limit": 50}, timeout=30)
        m = next((m for m in members(r.json() if r.ok else {})
                  if (m.get("name") or "").startswith(name)), None)
        iri = (m or {}).get("@id")
    print(f"[sched] our schedule IRI: {iri}")
    if not iri:
        return
    call("sched-get", "GET", iri)
    call("sched-update", "PUT", iri, json={"enabled": False})
    call("sched-delete", "DELETE", iri)
    verify_gone("sched", iri)


def group_search() -> None:
    call("search", "POST", "/api/search",
         json={"q": f"live-{RUN}", "index": ["alerts"], "size": 10})
    call("search-min", "POST", "/api/search", json={"q": "live", "index": ["alerts"]})


def group_feeds() -> None:
    """insert-feeds + ingest-feeds with our own indicator, then delete it."""
    r = S.get(f"{BASE}/api/3/indicators", params={"$limit": 1}, timeout=30)
    sample = next(iter(members(r.json() if r.ok else {})), None)
    print("[feeds] indicator sample keys:",
          sorted(k for k in sample if not k.startswith("@")) if sample else "(none)")
    value = f"live-{RUN}-feed.example.invalid"
    call("ingest", "POST", "/api/ingest-feeds/indicators",
         json={"data": [{"value": value, "type": "all"}]})
    call("insert", "POST", "/api/insert-feeds/indicators",
         json=[{"value": f"live-{RUN}-feed2.example.invalid", "type": "all"}])
    # cleanup: find ours, delete via the API-3 bulk delete (our own IRIs only)
    r = S.get(f"{BASE}/api/3/indicators", params={"$search": f"live-{RUN}", "$limit": 50}, timeout=30)
    iris = [m.get("@id") for m in members(r.json() if r.ok else {})
            if f"live-{RUN}" in (m.get("value") or "")]
    print(f"[feeds] our indicator IRIs: {iris}")
    if iris:
        call("feeds-del", "DELETE", "/api/3/delete/indicators", json=iris)
        for iri in iris:
            verify_gone("feeds", iri)


GROUPS = {
    "module": group_module,
    "picklists": group_picklists,
    "mcp": group_mcp,
    "schedules": group_schedules,
    "search": group_search,
    "feeds": group_feeds,
}


def main() -> int:
    which = sys.argv[1:] or list(GROUPS)
    mode = login()
    print(f"auth mode: {mode}")
    bad = 0
    try:
        for name in which:
            print(f"\n===== group: {name} =====")
            try:
                GROUPS[name]()
            except Exception as exc:  # keep probing other groups
                bad += 1
                print(f"[{name}] FAILED: {exc!r}")
    finally:
        # Belt-and-braces sweep: anything named live-<RUN>-* goes, by search.
        print("\n===== final sweep =====")
        for module in ("alerts", "indicators", "picklist_names"):
            r = S.get(f"{BASE}/api/3/{module}", params={"$search": f"live-{RUN}", "$limit": 50}, timeout=30)
            for m in members(r.json() if r.ok else {}):
                iri = m.get("@id")
                if iri and f"live-{RUN}" in (m.get("name") or m.get("value") or ""):
                    dr = S.delete(f"{BASE}{iri}", timeout=30)
                    print(f"  sweep {module} {iri} -> {dr.status_code}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
