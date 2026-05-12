"""Install hello-world, then probe whether `config` accepts a config name as
well as a config uuid on /api/integration/execute/. Cleans up after itself.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
from dotenv import load_dotenv
import requests, urllib3
urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
BASE = os.environ["FSR_BASE_URL"].rstrip("/")
KEY = os.environ["FSR_API_KEY"]
VERIFY = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
H = {"Authorization": f"API-KEY {KEY}"}
HJSON = {**H, "Content-Type": "application/json"}

NAME, VERSION = "hello-world", "1.0.4"
TGZ = ROOT / "tests" / "fixtures" / f"{NAME}-{VERSION}.tgz"

def call(body):
    r = requests.post(f"{BASE}/api/integration/execute/", headers=HJSON,
                      data=json.dumps(body), verify=VERIFY, timeout=30)
    txt = r.text if len(r.text) < 240 else r.text[:240] + "..."
    print(f"   {r.status_code}  {txt}")
    return r

print(f"[1] install {NAME} {VERSION}")
with open(TGZ, "rb") as f:
    r = requests.post(f"{BASE}/api/3/solutionpacks/install", headers=H,
                      params={"$type": "connector", "$replace": "true"},
                      files={"file": (TGZ.name, f, "application/gzip")},
                      verify=VERIFY, timeout=180)
inst = r.json()
connector_id = inst.get("id")
print(f"   installed id={connector_id} status={inst.get('status')!r}")

# Poll until installed
for _ in range(30):
    r = requests.get(f"{BASE}/api/integration/connectors/", headers=H,
                     params={"name": NAME}, verify=VERIFY, timeout=30)
    rows = r.json().get("data", [])
    if rows and rows[0].get("status") in ("installed", "Completed"):
        break
    time.sleep(1)

print("[2] create config")
config_name = "probe-hwcfg-by-name"
r = requests.post(f"{BASE}/api/integration/configuration/", headers=HJSON, verify=VERIFY,
                  json={"name": config_name, "connector": connector_id,
                        "config": {"default_greeting": "Hello", "salutation": "Mr."},
                        "default": False, "status": 1, "teams": []})
cfg = r.json()
cfg_uuid = cfg.get("config_id")
print(f"   config_id={cfg_uuid}  name={config_name!r}")

BASE_BODY = {"connector": NAME, "version": VERSION, "operation": "reverse_text",
             "params": {"input_text": "probe"}}

try:
    print("[3a] baseline with config=<uuid>")
    call({**BASE_BODY, "config": cfg_uuid})
    print("[3b] config=<config name>")
    call({**BASE_BODY, "config": config_name})
    print("[3c] no config field")
    call(BASE_BODY)
    print("[3d] config=null")
    call({**BASE_BODY, "config": None})
    print("[3e] config=<bogus uuid>")
    call({**BASE_BODY, "config": "00000000-0000-0000-0000-000000000000"})
    print("[3f] config=<unknown name>")
    call({**BASE_BODY, "config": "no-such-config"})
    print("[3g] no version (uuid config)")
    call({"connector": NAME, "operation": "reverse_text",
          "config": cfg_uuid, "params": {"input_text": "probe"}})
finally:
    print("[4] cleanup")
    requests.delete(f"{BASE}/api/integration/configuration/{cfg_uuid}/",
                    headers=H, verify=VERIFY, timeout=30)
    requests.delete(f"{BASE}/api/integration/connectors/{connector_id}/",
                    headers=H, verify=VERIFY, timeout=30)
    print("   cleanup done")
