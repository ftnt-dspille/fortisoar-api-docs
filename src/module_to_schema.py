"""
Derive OpenAPI schema fragments for FortiSOAR modules from the authoritative
model_metadatas endpoint:

    GET /api/3/model_metadatas?$limit=2147483647&$relationships=true

That walk returns every module plus its full `attributes` list, with enough
metadata to classify each field:

  - formType ∈ {text, textarea, html, richtext, integer, datetime, ...} → scalars
  - formType == "picklist"     → toOne IRI to /api/3/picklists/<uuid>;
                                 picklist taxonomy is in
                                 dataSource.query.filters[].value for
                                 listName__name
  - formType == "lookup"       → toOne IRI to /api/3/<module>/<uuid>;
                                 referenced module in `type`
  - formType == "manyToMany"   → array of IRIs to /api/3/<module>/<uuid>;
                                 referenced module in `type`, collection=true
  - formType == "oneToMany"    → array of IRIs (rare, treated like manyToMany)
  - formType == "manyToOne"    → single IRI (rare, treated like lookup)

Usage:
    python src/module_to_schema.py incidents tasks comments
    python src/module_to_schema.py --all-priority           # incidents/tasks/comments
    python src/module_to_schema.py --raw incidents          # dump raw attribute list

Prints a Python literal suitable for pasting into SCHEMAS in build_curated.py.
The script intentionally emits *every* field — hand-curate the output down to
the most-used 15-25 fields before committing, in the same spirit as the
existing `Alert` schema.
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

PRIORITY_MODULES = ["incidents", "tasks", "comments"]

# Map FortiSOAR formType → OpenAPI scalar shape. Anything not listed falls
# back to string with a description hint.
SCALAR_FORM_TYPES: dict[str, dict[str, Any]] = {
    "text":      {"type": ["string", "null"]},
    "textarea":  {"type": ["string", "null"]},
    "html":      {"type": ["string", "null"], "description": "HTML body."},
    "richtext":  {"type": ["string", "null"], "description": "HTML body (rich-text editor)."},
    "integer":   {"type": ["integer", "null"]},
    "decimal":   {"type": ["number", "null"]},
    "float":     {"type": ["number", "null"]},
    "boolean":   {"type": ["boolean", "null"]},
    "checkbox":  {"type": ["boolean", "null"]},
    "datetime":  {"type": ["number", "null"],
                  "description": "Epoch seconds (UTC). May include fractional component."},
    "date":      {"type": ["string", "null"], "format": "date"},
    "json":      {"type": ["object", "null"]},
    "object":    {"type": ["object", "null"]},
}


def _session() -> tuple[requests.Session, str, int]:
    load_dotenv(ROOT / ".env")
    base = os.environ.get("FSR_BASE_URL", "").rstrip("/")
    if not base:
        sys.exit("FSR_BASE_URL missing from .env")
    verify = os.environ.get("FSR_VERIFY_TLS", "false").lower() == "true"
    timeout = int(os.environ.get("FSR_TEST_TIMEOUT", "60"))
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s = requests.Session()
    s.verify = verify
    user = os.environ.get("FSR_USERNAME", "")
    pw = os.environ.get("FSR_PASSWORD", "")
    api_key = os.environ.get("FSR_API_KEY", "")
    if user and pw:
        r = s.post(f"{base}/auth/authenticate",
                   json={"credentials": {"loginid": user, "password": pw}},
                   timeout=timeout)
        r.raise_for_status()
        s.headers["Authorization"] = f"Bearer {r.json()['token']}"
    elif api_key:
        s.headers["API-KEY"] = api_key
    else:
        sys.exit("No auth: set FSR_USERNAME+FSR_PASSWORD or FSR_API_KEY in .env")
    return s, base, timeout


def fetch_all_metadata(s: requests.Session, base: str, timeout: int) -> list[dict]:
    """One round-trip pulls every module + its attribute list."""
    r = s.get(
        f"{base}/api/3/model_metadatas",
        params={"$limit": 2147483647, "$relationships": "true"},
        timeout=max(timeout, 60),
    )
    r.raise_for_status()
    return r.json().get("hydra:member", [])


def _picklist_taxonomy(attr: dict) -> str | None:
    """Pull the `AlertSeverity`-style taxonomy name out of a picklist attribute."""
    ds = attr.get("dataSource") or {}
    for f in (ds.get("query") or {}).get("filters", []):
        if f.get("field") == "listName__name":
            return f.get("value")
    return None


def _attr_to_property(attr: dict) -> dict[str, Any]:
    name = attr.get("name", "")
    form = attr.get("formType")
    typ = attr.get("type")
    is_collection = bool(attr.get("collection"))
    tooltip = (attr.get("tooltip") or "").strip()
    writeable = attr.get("writeable", True)
    identifier = attr.get("identifier", False)

    if form == "picklist":
        taxonomy = _picklist_taxonomy(attr) or "?"
        prop: dict[str, Any] = {
            "type": ["string", "null"],
            "description": f"IRI to a `/api/3/picklists/<uuid>` value in the **{taxonomy}** taxonomy.",
        }
    elif form in ("lookup", "manyToOne") and not is_collection:
        prop = {
            "type": ["string", "null"],
            "description": f"IRI to `/api/3/{typ}/<uuid>`.",
        }
    elif form in ("manyToMany", "oneToMany") or is_collection:
        prop = {
            "type": "array",
            "items": {"$ref": "#/components/schemas/IRI"},
            "description": (
                f"Array of IRIs to `/api/3/{typ}/<uuid>`. "
                "On GET with `?$relationships=true` each entry is expanded to the full record."
            ),
        }
    elif form in SCALAR_FORM_TYPES:
        prop = dict(SCALAR_FORM_TYPES[form])
    else:
        prop = {"type": ["string", "null"]}
        if form:
            prop["description"] = f"formType={form}"

    if tooltip:
        existing = prop.get("description", "")
        prop["description"] = f"{tooltip} {existing}".strip() if existing else tooltip
    if identifier:
        prop["description"] = (prop.get("description", "") + " Identifier field.").strip()
    if not writeable:
        prop["readOnly"] = True
    return prop


def module_to_schema(meta: dict, friendly_name: str) -> dict[str, Any]:
    attrs = meta.get("attributes", [])
    properties: dict[str, Any] = {
        "@id": {"$ref": "#/components/schemas/IRI"},
        "@type": {"type": "string", "example": friendly_name},
        "uuid": {"$ref": "#/components/schemas/UUID"},
    }
    # Sort by orderIndex (UI display order) when present.
    attrs_sorted = sorted(attrs, key=lambda a: a.get("orderIndex") or 0)
    for a in attrs_sorted:
        name = a.get("name")
        if not name or name in properties:
            continue
        properties[name] = _attr_to_property(a)

    article = "An" if friendly_name[:1].lower() in "aeiou" else "A"
    desc_parts = [f"{article} {friendly_name} record. Field set derived from "
                  f"`GET /api/3/model_metadatas?$relationships=true`."]
    default_sort = meta.get("defaultSort") or []
    if default_sort:
        desc_parts.append(f"Default sort: `{default_sort}`.")
    uc = meta.get("uniqueConstraint") or []
    if uc:
        desc_parts.append(f"Unique constraints: `{uc}`.")
    flags = [k for k in ("ownable", "taggable", "queueable", "softDeleteable", "archivable")
             if meta.get(k)]
    if flags:
        desc_parts.append("Flags: " + ", ".join(flags) + ".")

    return {
        "type": "object",
        "description": " ".join(desc_parts),
        "properties": properties,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", nargs="*",
                    help="Plural module names (e.g. incidents, tasks, comments).")
    ap.add_argument("--all-priority", action="store_true",
                    help=f"Shorthand for {' '.join(PRIORITY_MODULES)}.")
    ap.add_argument("--raw", action="store_true",
                    help="Print raw attribute list instead of derived schema.")
    args = ap.parse_args()

    wanted = list(args.modules)
    if args.all_priority:
        wanted = PRIORITY_MODULES
    if not wanted:
        ap.error("supply module names or --all-priority")

    s, base, t = _session()
    all_meta = fetch_all_metadata(s, base, t)
    by_type = {m["type"]: m for m in all_meta}

    out: dict[str, dict] = {}
    for plural in wanted:
        meta = by_type.get(plural)
        if not meta:
            sys.exit(f"module {plural!r} not found in model_metadatas")
        friendly = "".join(p.capitalize() for p in plural.rstrip("s").split("_")) or plural
        # Heuristic friendlies for the irregulars:
        friendly = {"incidents": "Incident", "tasks": "Task", "comments": "Comment",
                    "alerts": "Alert", "indicators": "Indicator",
                    "assets": "Asset", "people": "Person"}.get(plural, friendly)
        if args.raw:
            print(f"# --- {plural} ({len(meta.get('attributes', []))} attributes) ---")
            print(json.dumps(meta.get("attributes", []), indent=2))
            continue
        out[friendly] = module_to_schema(meta, friendly)
    if not args.raw:
        print(json.dumps(out, indent=4))


if __name__ == "__main__":
    main()
