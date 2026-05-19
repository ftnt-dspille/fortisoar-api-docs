"""Probe a live FortiSOAR appliance for STIX/TAXII surface area.

Tries common TAXII 2.x discovery paths, TIM solution-pack endpoints, and
plausible STIX import/export routes. Reports status + content-type +
body excerpt for each, with and without trailing slashes (HMAC trap).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

BASE = os.environ.get("FSR_BASE_URL", "").rstrip("/")
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
TIMEOUT = int(os.environ.get("FSR_TEST_TIMEOUT", "20"))
API_KEY = os.environ.get("FSR_API_KEY", "")
USER = os.environ.get("FSR_USERNAME", "")
PW = os.environ.get("FSR_PASSWORD", "")

if not BASE:
    sys.exit("FSR_BASE_URL missing")

auth_header = ""
if USER and PW:
    r = requests.post(f"{BASE}/auth/authenticate",
                      json={"credentials": {"loginid": USER, "password": PW}},
                      verify=VERIFY, timeout=TIMEOUT)
    if r.ok and r.json().get("token"):
        auth_header = f"Bearer {r.json()['token']}"
if not auth_header and API_KEY:
    auth_header = f"API-KEY {API_KEY}"
if not auth_header:
    sys.exit("no auth")

# Paths to probe. TAXII discovery is the canonical entry point; the rest
# cover plausible TIM solution-pack routes and STIX bundle endpoints.
CANDIDATES = [
    # TAXII 2.x discovery / api-root / collections
    "/api/taxii2",
    "/api/taxii2/api",
    "/api/taxii2/api/collections",
    "/api/taxii/discovery",
    "/api/taxii/api-root",
    "/api/taxii/collections",
    "/taxii2",
    "/taxii2/api",
    "/taxii/discovery",
    # FortiSOAR threat-intel module-style
    "/api/3/threat_intel_feeds",
    "/api/3/indicators",
    "/api/3/stix_indicators",
    "/api/3/stix_objects",
    "/api/3/stix_bundles",
    "/api/3/threat_feeds",
    "/api/3/feed_configurations",
    "/api/3/feed_config",
    "/api/3/sources",
    "/api/3/feed_sources",
    # Ingest / bundle import
    "/api/ingest-feeds",
    "/api/ingest-feeds/stix",
    "/api/ingest-feeds/bundle",
    "/api/threat-intel/import",
    "/api/threat-intel/stix",
    "/api/stix/import",
    "/api/stix/bundle",
    # TIM-style
    "/api/tim",
    "/api/tim/feeds",
    "/api/tim/indicators",
    "/api/tim/taxii",
    # Discovery / help
    "/api/3/contexts/StixIndicator",
    "/api/3/contexts/ThreatIntelFeed",
    "/api/3/contexts/Indicator",
    "/api/3/contexts/Source",
]

# Pull /api/3/docs.jsonld to find any module names with stix/threat/indicator
# tokens — much higher signal than guessing.
print(f"== Probing {BASE} ==\n")
try:
    r = requests.get(f"{BASE}/api/3/docs.jsonld",
                     headers={"Authorization": auth_header, "Accept": "application/json"},
                     verify=VERIFY, timeout=TIMEOUT)
    if r.ok:
        body = r.text.lower()
        hits = set()
        for kw in ("stix", "taxii", "threat", "indicator", "feed", "ioc", "campaign",
                   "malware", "intrusion", "tlp", "observable"):
            # Find @id values containing keyword
            import re
            for m in re.finditer(rf'"@id"\s*:\s*"([^"]*{kw}[^"]*)"', r.text, re.I):
                hits.add(m.group(1))
        print(f"docs.jsonld @id hits ({len(hits)}):")
        for h in sorted(hits):
            print(f"  {h}")
        print()
    else:
        print(f"docs.jsonld -> {r.status_code}\n")
except Exception as e:
    print(f"docs.jsonld error: {e}\n")

print("== Direct path probes ==")
headers = {"Authorization": auth_header, "Accept": "application/taxii+json;version=2.1, application/json"}
for path in CANDIDATES:
    for p in (path, path + "/") if not path.endswith("/") else (path,):
        try:
            r = requests.get(f"{BASE}{p}", headers=headers, verify=VERIFY, timeout=TIMEOUT)
            ct = r.headers.get("Content-Type", "")[:60]
            body = r.text[:140].replace("\n", " ")
            print(f"  {r.status_code:>3}  {p:<55}  ct={ct:<35}  {body}")
        except Exception as e:
            print(f"  ERR  {p:<55}  {e}")
