"""Probe /api/integration/execute/ to learn which body fields are truly required.

Strategy: send variants with one field omitted at a time and observe the error.
We don't need a working config; we just need to see which fields trigger
validation errors *before* operation lookup.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
from dotenv import load_dotenv
import requests
import urllib3
urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

BASE = os.environ["FSR_BASE_URL"].rstrip("/")
KEY = os.environ["FSR_API_KEY"]
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
H = {"Authorization": f"API-KEY {KEY}", "Content-Type": "application/json"}

BASE_BODY = {
    "connector": "cyops_utilities",
    "version": "3.7.0",
    "operation": "system_info",
    "config": "ffa10d39-8465-4aad-83e5-793372ec4362",
    "params": {},
}

VARIANTS = [
    ("baseline (all fields, bogus config uuid)", BASE_BODY),
    ("empty body", {}),
    ("missing connector", {k: v for k, v in BASE_BODY.items() if k != "connector"}),
    ("missing version", {k: v for k, v in BASE_BODY.items() if k != "version"}),
    ("missing operation", {k: v for k, v in BASE_BODY.items() if k != "operation"}),
    ("missing config", {k: v for k, v in BASE_BODY.items() if k != "config"}),
    ("missing params", {k: v for k, v in BASE_BODY.items() if k != "params"}),
    ("params = {}", {**BASE_BODY, "params": {}}),
    ("version as null", {**BASE_BODY, "version": None}),
    ("config as null", {**BASE_BODY, "config": None}),
]

for label, body in VARIANTS:
    r = requests.post(f"{BASE}/api/integration/execute/", headers=H,
                      data=json.dumps(body), verify=VERIFY, timeout=30)
    txt = r.text
    if len(txt) > 240:
        txt = txt[:240] + "..."
    print(f"-- {label}")
    print(f"   {r.status_code}  {txt}")
