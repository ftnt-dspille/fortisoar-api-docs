"""Probe whether FortiSOAR's TAXII 2.1 server honors the standard
`match[*]` query parameters on `/api/taxii/1/collections/{id}/objects`.

Picks a non-empty collection, gets a baseline object listing, then
re-issues with each match filter and compares counts / types.
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

BASE = os.environ.get("FSR_BASE_URL", "").rstrip("/")
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
TIMEOUT = int(os.environ.get("FSR_TEST_TIMEOUT", "30"))
USER = os.environ.get("FSR_USERNAME", "")
PW = os.environ.get("FSR_PASSWORD", "")
API_KEY = os.environ.get("FSR_API_KEY", "")

if not BASE:
    sys.exit("FSR_BASE_URL missing")

auth = ""
if USER and PW:
    r = requests.post(f"{BASE}/auth/authenticate",
                      json={"credentials": {"loginid": USER, "password": PW}},
                      verify=VERIFY, timeout=TIMEOUT)
    if r.ok and r.json().get("token"):
        auth = f"Bearer {r.json()['token']}"
if not auth and API_KEY:
    auth = f"API-KEY {API_KEY}"
if not auth:
    sys.exit("no auth")
H = {"Authorization": auth}


def get(path, **params):
    return requests.get(f"{BASE}{path}", headers=H, params=params,
                        verify=VERIFY, timeout=TIMEOUT, allow_redirects=False)


# 1. Find a non-empty collection.
cols = get("/api/taxii/1/collections").json().get("collections", [])
chosen = None
for c in cols:
    cid = c.get("id")
    body = get(f"/api/taxii/1/collections/{cid}/objects", limit=200).json()
    if (body.get("totalItems") or 0) > 0:
        chosen = (cid, body)
        break
if not chosen:
    sys.exit("no non-empty collection found")

cid, baseline = chosen
objs = baseline.get("objects") or []
types = Counter(o.get("type") for o in objs)
ids   = [o.get("id") for o in objs if o.get("id")]
print(f"collection {cid}: {baseline.get('totalItems')} objects, types={dict(types)}")

# Pick a type that has more than one and at least one other type also present
candidate_type = None
for t, n in types.most_common():
    if 0 < n < sum(types.values()):
        candidate_type = t
        break
if candidate_type is None and types:
    candidate_type = next(iter(types))

print("\n--- probe: match[type] ---")
for t in [candidate_type, "bogus_type_xyz"] if candidate_type else ["indicator"]:
    r = get(f"/api/taxii/1/collections/{cid}/objects", **{"match[type]": t, "limit": 200})
    body = r.json() if r.ok else {}
    got_types = Counter(o.get("type") for o in (body.get("objects") or []))
    print(f"  match[type]={t!r:20s}  status={r.status_code}  total={body.get('totalItems')!r}  types={dict(got_types)}")

print("\n--- probe: match[id] ---")
if ids:
    target = ids[0]
    r = get(f"/api/taxii/1/collections/{cid}/objects", **{"match[id]": target})
    body = r.json() if r.ok else {}
    got = body.get("objects") or []
    print(f"  match[id]={target}  status={r.status_code}  total={body.get('totalItems')!r}  returned_ids={[o.get('id') for o in got]}")

print("\n--- probe: match[version] ---")
for v in ["last", "first", "all"]:
    r = get(f"/api/taxii/1/collections/{cid}/objects", **{"match[version]": v, "limit": 200})
    body = r.json() if r.ok else {}
    print(f"  match[version]={v!r:6s} status={r.status_code}  total={body.get('totalItems')!r}")

print("\n--- probe: match[spec_version] ---")
for sv in ["2.1", "2.0"]:
    r = get(f"/api/taxii/1/collections/{cid}/objects", **{"match[spec_version]": sv, "limit": 200})
    body = r.json() if r.ok else {}
    print(f"  match[spec_version]={sv!r}  status={r.status_code}  total={body.get('totalItems')!r}")

print("\n--- probe: comma-separated match[type] (TAXII 2.1 allows OR) ---")
if len(types) >= 2:
    a, b = list(types)[:2]
    r = get(f"/api/taxii/1/collections/{cid}/objects", **{"match[type]": f"{a},{b}", "limit": 200})
    body = r.json() if r.ok else {}
    got_types = Counter(o.get("type") for o in (body.get("objects") or []))
    print(f"  match[type]={a},{b}  status={r.status_code}  total={body.get('totalItems')!r}  types={dict(got_types)}")
