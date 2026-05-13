"""
Derive OpenAPI schema fragments for FortiSOAR modules by walking the Hydra
context at GET /api/3/contexts/<Entity>.

Usage:
    python src/hydra_to_schema.py Alert Incident Indicator Task Asset Person
    python src/hydra_to_schema.py --all-priority   # the six above
    python src/hydra_to_schema.py --raw Alert      # dump raw context for inspection

Emits a Python literal suitable for pasting into SCHEMAS in build_curated.py.
Hand-edit the result: prune to the most-used fields, add picklist hints, etc.
The point of the tool is to surface the *real* field set, not to ship every
field verbatim.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

PRIORITY_MODULES = ["Alert", "Incident", "Indicator", "Task", "Asset", "Person"]

# Hydra XSD ranges → OpenAPI type. Anything else falls back to string.
XSD_TO_OPENAPI: dict[str, dict[str, Any]] = {
    "xmls:string": {"type": ["string", "null"]},
    "xmls:boolean": {"type": ["boolean", "null"]},
    "xmls:integer": {"type": ["integer", "null"]},
    "xmls:int": {"type": ["integer", "null"]},
    "xmls:long": {"type": ["integer", "null"], "format": "int64"},
    "xmls:float": {"type": ["number", "null"]},
    "xmls:double": {"type": ["number", "null"]},
    "xmls:decimal": {"type": ["number", "null"]},
    "xmls:date": {"type": ["string", "null"], "format": "date"},
    "xmls:dateTime": {"type": ["integer", "null"], "format": "int64",
                      "description": "Epoch milliseconds (UTC)."},
}


def _session() -> tuple[requests.Session, str, bool, int]:
    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    if not base:
        sys.exit("FSR_BASE_URL missing from .env")
    verify = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
    timeout = int(os.environ.get("FSR_TEST_TIMEOUT", "20"))
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s = requests.Session()
    s.verify = verify
    # Hydra context endpoints are JWT-only on 7.6.x (API-KEY returns 403),
    # so prefer username/password if available.
    user = os.environ.get("FSR_USERNAME", "")
    pw = os.environ.get("FSR_PASSWORD", "")
    api_key = os.environ.get("FSR_API_KEY", "")
    if user and pw:
        r = s.post(f"{base}/auth/authenticate", json={
            "credentials": {"loginid": user, "password": pw}
        }, timeout=timeout)
        r.raise_for_status()
        s.headers["Authorization"] = f"Bearer {r.json()['token']}"
    elif api_key:
        s.headers["API-KEY"] = api_key
    else:
        sys.exit("No auth: set FSR_USERNAME+FSR_PASSWORD (preferred) or FSR_API_KEY")
    return s, base, verify, timeout


def fetch_context(s: requests.Session, base: str, entity: str, timeout: int) -> dict:
    r = s.get(f"{base}/api/3/contexts/{entity}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def context_to_schema(ctx: dict, entity: str) -> dict[str, Any]:
    """Turn a Hydra @context dict into an OpenAPI object schema."""
    container = ctx.get("@context", ctx)
    properties: dict[str, Any] = {
        "@id": {"$ref": "#/components/schemas/IRI"},
        "@type": {"type": "string", "example": entity},
        "uuid": {"$ref": "#/components/schemas/UUID"},
    }
    for key, val in container.items():
        if key.startswith("@") or key.startswith("hydra:"):
            continue
        if not isinstance(val, dict):
            continue
        rng = val.get("@type") or ""
        idref = val.get("@id", "")
        if rng in XSD_TO_OPENAPI:
            properties[key] = dict(XSD_TO_OPENAPI[rng])
        elif rng == "@id":
            properties[key] = {
                "type": ["string", "null"],
                "description": f"IRI reference ({idref}).",
            }
        else:
            properties[key] = {"type": ["string", "null"]}
        if "createDate" in key or "modifyDate" in key or key.endswith("Date"):
            properties[key].setdefault("format", "int64")
    return {
        "type": "object",
        "description": f"A {entity} record. Field set derived from GET /api/3/contexts/{entity}.",
        "properties": properties,
    }


def emit_python_literal(schemas: dict[str, dict]) -> str:
    return json.dumps(schemas, indent=4)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("entities", nargs="*")
    ap.add_argument("--all-priority", action="store_true")
    ap.add_argument("--raw", action="store_true",
                    help="Print raw context JSON instead of derived schema.")
    args = ap.parse_args()

    entities = list(args.entities)
    if args.all_priority:
        entities = PRIORITY_MODULES
    if not entities:
        ap.error("supply entity names or --all-priority")

    s, base, _, timeout = _session()
    out: dict[str, dict] = {}
    for ent in entities:
        ctx = fetch_context(s, base, ent, timeout)
        if args.raw:
            print(f"# --- {ent} ---")
            print(json.dumps(ctx, indent=2))
            continue
        out[ent] = context_to_schema(ctx, ent)
    if not args.raw:
        print(emit_python_literal(out))


if __name__ == "__main__":
    main()
