"""Probe batch 3: clone a playbook into a minimal live- ManualInput gate,
trigger it, and capture the paused-input lifecycle (detail + wfinput_resume +
manual-wf-input DELETE) before deleting everything this run created.

Safety: the clone is named live-<run>-..., its trigger route is live-<run>-...,
both triggered runs and both pending inputs are ours (one consumed via
wfinput_resume, one abandoned via DELETE), and the clone is deleted in the end.
The post-input branch is a single SetVariable step, so a resumed run does no
real work.

Run:
    python scripts/probe_manual_input.py            # full lifecycle
    python scripts/probe_manual_input.py --create   # create + trigger only
    python scripts/probe_manual_input.py --cleanup  # delete leftovers by name
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
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
RUN = _uuid.uuid4().hex[:8]
PB_NAME = f"live-{RUN}-input-test"
SOURCE_NAME = "E2E - Manual Input"  # purpose-built template: trigger -> ManualInput -> trivial end
S = requests.Session()
S.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
S.verify = VERIFY

def login() -> None:
    r = S.post(f"{BASE}/auth/authenticate", verify=VERIFY, timeout=30,
               json={"credentials": {"loginid": os.environ["FSR_USERNAME"],
                                     "password": os.environ["FSR_PASSWORD"]}})
    S.headers["Authorization"] = f"Bearer {r.json()['token']}"


def call(label, method, path, **kw):
    r = S.request(method, f"{BASE}{path}", timeout=90, **kw)
    try:
        body = r.json() if r.content else None
    except ValueError:
        body = f"<non-json {len(r.content)} bytes>"
    print(f"[{label}] {method} {path} -> {r.status_code}")
    print("   ", json.dumps(body)[:500] if body is not None else "(no body)")
    return r.status_code, body


def find_ours() -> dict | None:
    r = S.get(f"{BASE}/api/3/workflows", params={"name": PB_NAME, "$limit": 5}, timeout=30)
    for m in (r.json() or {}).get("hydra:member", []):
        if isinstance(m, dict) and m.get("name") == PB_NAME:
            return m
    return None


def user_iri() -> str | None:
    r = S.get(f"{BASE}/api/3/people", params={"$limit": 50}, timeout=30)
    members = [m for m in (r.json() or {}).get("hydra:member", []) if isinstance(m, dict)]
    if not members:
        return None
    for m in members:  # prefer an admin (same recipe as pyfsr)
        name = f"{m.get('firstname') or ''} {m.get('lastname') or ''}".lower()
        if "admin" in name:
            return m["@id"]
    return members[0]["@id"]


def pending_input(run_pk: str | None = None) -> dict | None:
    r = S.get(f"{BASE}/api/wf/api/manual-wf-input/", params={"format": "json", "limit": 50}, timeout=30)
    rows = r.json() if r.content else []
    rows = rows if isinstance(rows, list) else (rows or {}).get("hydra:member") or []
    for row in rows:
        # the row's `workflow` field is the numeric run id — key ours off the
        # task_id we just triggered, not text markers
        if run_pk is not None and str(row.get("workflow")) == str(run_pk):
            return row
    return None


def run_pk_for(task_id: str) -> str | None:
    for _ in range(6):  # the run registers a beat after the trigger returns
        r = S.post(f"{BASE}/api/wf/api/workflows/log_list/", params={"task_id": task_id, "limit": 1},
                   json={}, timeout=30)
        rows = (r.json() or {}).get("hydra:member") or []
        if rows:
            return str((rows[0].get("@id") or "").rstrip("/").rsplit("/", 1)[-1])
        time.sleep(2)
    return None


def members(body):
    if isinstance(body, dict):
        return [m for m in (body.get("hydra:member") or []) if isinstance(m, dict)]
    return [m for m in (body or []) if isinstance(m, dict)]


def create_clone() -> dict:
    """Clone the E2E template as-is.

    No transform and no post-clone step rewiring is needed: pyfsr's clone
    substitutes old->new uuids across the whole serialized definition, which
    includes the response_mapping options' step_iri references, and the E2E
    template's flow is already trigger -> ManualInput -> trivial SetVariable.
    (Gutting a heavier template instead — pruning to three steps and
    rebuilding routes — clones fine but its resume answers 500; the pruned
    branch's steps crash the inline resume execution.)
    """
    from pyfsr import FortiSOAR
    c = FortiSOAR(BASE, username=os.environ["FSR_USERNAME"], password=os.environ["FSR_PASSWORD"],
                  verify_ssl=VERIFY, suppress_insecure_warnings=True)
    r = S.get(f"{BASE}/api/3/workflows", params={"name": SOURCE_NAME, "$limit": 10}, timeout=30)
    src_uuid = next((m.get("uuid") for m in members(r.json()) if m.get("name") == SOURCE_NAME), None)
    if not src_uuid:
        raise SystemExit(f"template playbook {SOURCE_NAME!r} not found on this appliance")

    pb = c.playbooks.clone(src_uuid, PB_NAME, is_active=True)
    print(f"[clone] created {pb.get('@id')} (uuid={pb.get('uuid')})")
    return pb


def main() -> int:
    login()
    if "--cleanup" in sys.argv:
        m = find_ours()
        if m:
            st, _ = call("cleanup-del", "DELETE", f"/api/3/workflows/{m['uuid']}")
            print("cleanup:", st)
        else:
            print("nothing to clean up")
        return 0

    pb = create_clone()
    uuid_ = pb.get("uuid")

    st, trig = call("trigger", "POST", f"/api/triggers/1/notrigger/{uuid_}", json={})
    task_id = (trig or {}).get("task_id")
    run_pk = run_pk_for(task_id) if task_id else None
    print(f"[poll] waiting for run {run_pk} to pause on the manual input")
    row = None
    for _ in range(20):
        time.sleep(3)
        row = pending_input(run_pk)
        if row:
            break
    if not row:
        print("[poll] no pending input appeared")
        return 1
    print("[poll] pending input:", json.dumps(row)[:500])

    mi_id = row.get("id")
    st, _ = call("mi-detail", "GET", f"/api/wf/api/manual-wf-input/{mi_id}/", params={"format": "json"})
    det = S.get(f"{BASE}/api/wf/api/manual-wf-input/{mi_id}/", params={"format": "json"}, timeout=30).json()
    print("[mi] detail keys:", sorted(det.keys()) if isinstance(det, dict) else det)
    step_id = det.get("step_id") or det.get("stepId")
    opts = ((det.get("response_mapping") or det.get("responseMapping") or {}).get("options")) or []
    opt = opts[0] if opts else {}
    wf_field = det.get("workflow") or row.get("workflow")
    wf_num = str(wf_field).rstrip("/").rsplit("/", 1)[-1] if isinstance(wf_field, str) else wf_field
    u_iri = user_iri()
    print(f"[resume] workflow={wf_num} step_id={step_id} mi_id={mi_id} option={opt.get('option')} step_iri={opt.get('step_iri')}")
    st, res = call("resume", "POST", f"/api/wf/api/workflows/{wf_num}/wfinput_resume/",
                   params={"format": "json"},
                   json={"input": {}, "step_iri": opt.get("step_iri"), "step_id": step_id,
                         "manual_input_id": mi_id, "user": u_iri})

    # second run: abandon via DELETE (the op under test)
    st, trig2 = call("trigger2", "POST", f"/api/triggers/1/notrigger/{uuid_}", json={})
    task2 = (trig2 or {}).get("task_id")
    run_pk2 = run_pk_for(task2) if task2 else None
    row2 = None
    for _ in range(20):
        time.sleep(3)
        row2 = pending_input(run_pk2)
        if row2:
            break
    if row2:
        call("mi-delete", "DELETE", f"/api/wf/api/manual-wf-input/{row2['id']}/",
             params={"format": "json"})
    else:
        print("[mi-delete] no second pending input appeared")

    st, _ = call("pb-delete", "DELETE", f"/api/3/workflows/{uuid_}")
    return 0 if st < 300 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        m = find_ours()
        if m and "--create" not in sys.argv and "--cleanup" not in sys.argv:
            S.delete(f"{BASE}/api/3/workflows/{m['uuid']}", timeout=30)
            print("[finally] removed playbook", m["uuid"])
