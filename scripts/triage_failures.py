#!/usr/bin/env python3
"""Pull failing ops out of build/curated_verification.json for LLM-driven triage.

A "failing" op is one that ran against the appliance but did NOT return 2xx on
EITHER apikey or jwt. Skipped ops (no fixture, doc templates, permanent skips)
are reported separately, since those need a different kind of fix.

Output is a single Markdown brief with N op cases and a fix-instruction prelude
the LLM can follow without re-deriving the workflow each session.

Usage:
    python scripts/triage_failures.py                # 4 random failing ops
    python scripts/triage_failures.py -n 3           # pick 3
    python scripts/triage_failures.py -n 5 --seed 7  # reproducible pick
    python scripts/triage_failures.py --include-skipped
    python scripts/triage_failures.py --tag Workflows
    python scripts/triage_failures.py -o triage.md
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VERIFICATION = REPO_ROOT / "build" / "curated_verification.json"


FIX_INSTRUCTIONS = """\
## How to fix these ops

You are triaging FortiSOAR curated-spec ops that failed live verification on
both `apikey` and `jwt`. The curated spec lives in `src/build_curated.py`; the
verifier in `src/verify_curated.py` produced the cases below.

For each op, decide which bucket it falls into and apply the matching fix.

### Bucket A - the spec is wrong (path / params / body shape off)
Symptoms: 400 with a parser/validation message, 404 on a path that should
exist, "Unknown field" / "Required field missing" in the response.
Fix:
  1. Open `src/build_curated.py` and locate the `PATHS["<path>"]` entry.
  2. Correct the path, parameters, requestBody schema, or `example` payload.
  3. If the verifier is sending the wrong fixture, update the example so the
     next run hits a real shape.
  4. Rebuild: `python src/build_curated.py`.
  5. Re-verify just this op (or the whole spec) with `python src/verify_curated.py`.

### Bucket B - the op is auth-mode-restricted by design
Symptoms: one mode returns 2xx-shaped data, the other returns 401/403 with a
clean "AccessDeniedException" or HMAC error - and that asymmetry is intentional
(e.g. `/api/wf/api/workflows/count` is HMAC-only; `/api/auth/license` is
JWT-only on most boxes).
Fix:
  1. In `src/build_curated.py`, add a one-line `description:` callout naming
     the restriction ("HMAC-only", "JWT-only on tested boxes", etc.).
  2. If only one mode is expected to ever pass, mark it in the op's
     verifier-side allowlist (TBD: see `verify_curated.py` for the
     `auth-restricted` map - extend it so the verifier stops counting the
     intended-failing mode as a fail).
  3. Rebuild + re-verify.

### Bucket C - placeholder fixture is wrong / stale
Symptoms: 404 on a `{uuid}`/`{pk}` path, or 400 because the fixture isn't a
valid IRI for this appliance.
Fix:
  1. In `verify_curated.py`, find where placeholders are filled. Either widen
     the discovery query (list endpoint -> grab a real uuid first) or hardcode
     a known-good fixture for this op.
  2. Rebuild + re-verify.

### Bucket D - real appliance-side bug or env issue
Symptoms: 500 InternalServerError, "Check log 'prod.log'", non-JSON HTML
error page.
Fix:
  - Document it. Add a `description:` note: "**Heads-up:** returns 500 on
    7.x.y; root cause unknown." Do NOT silently mark the op verified.
  - File-level TODOs go in `TODOS.md`.

### Anti-patterns - do NOT do these
- Don't delete the op from the spec to make verification pass.
- Don't relax schema_ok by removing the response schema; fix the schema.
- Don't change the verifier to accept the wrong status as success.
"""


def load_verification(path: Path) -> dict[str, Any]:
    if not path.exists():
        sys.exit(f"verification file not found: {path}\nRun `python src/verify_curated.py` first.")
    return json.loads(path.read_text())


def is_2xx(entry: dict[str, Any]) -> bool:
    status = entry.get("status")
    return isinstance(status, int) and 200 <= status < 300


def select_failing(ops: dict[str, dict[str, Any]], tag_filter: str | None) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for key, op in ops.items():
        if "skipped" in op:
            continue
        by_auth = op.get("by_auth") or {}
        if not by_auth:
            continue
        if any(is_2xx(r) for r in by_auth.values()):
            continue
        if tag_filter and tag_filter not in (op.get("tags") or []):
            continue
        out.append((key, op))
    return out


def select_skipped(ops: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    return [(k, v) for k, v in ops.items() if "skipped" in v]


def render_op(key: str, op: dict[str, Any]) -> str:
    method, path = key.split(" ", 1)
    lines: list[str] = []
    lines.append(f"### {key}")
    lines.append("")
    lines.append(f"- **Tags:** {', '.join(op.get('tags') or []) or '-'}")
    lines.append(f"- **Summary:** {op.get('summary') or '-'}")
    lines.append(f"- **Mutating:** {op.get('mutating', False)}")
    lines.append("")

    by_auth = op.get("by_auth") or {}
    for mode in ("apikey", "jwt"):
        result = by_auth.get(mode)
        if not result:
            lines.append(f"#### {mode}: not attempted")
            lines.append("")
            continue
        status = result.get("status")
        elapsed = result.get("elapsed_ms")
        lines.append(f"#### {mode}: HTTP {status} ({elapsed} ms)")
        sent = result.get("sent_request") or {}
        lines.append("")
        lines.append("Sent request:")
        lines.append("```json")
        lines.append(json.dumps(sent, indent=2))
        lines.append("```")
        lines.append("")
        lines.append("Response:")
        lines.append("```json")
        sample = result.get("sample_response")
        body = json.dumps(sample, indent=2) if sample is not None else '"<empty>"'
        if len(body) > 4000:
            body = body[:4000] + "\n... <truncated>"
        lines.append(body)
        lines.append("```")
        schema_errs = result.get("schema_errors") or []
        if schema_errs:
            lines.append("")
            lines.append(f"Schema errors: `{schema_errs}`")
        lines.append("")

    lines.append(f"**Spec lookup:** `grep -n 'PATHS\\[\"{path}\"' src/build_curated.py`")
    lines.append("")
    return "\n".join(lines)


def render_skipped(key: str, op: dict[str, Any]) -> str:
    return f"- `{key}` - {op.get('skipped')}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-n", "--count", type=int, default=4, help="Number of failing ops to include (default 4)")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducible selection")
    p.add_argument("--tag", default=None, help="Only consider ops carrying this tag")
    p.add_argument("--include-skipped", action="store_true", help="Also list every skipped op (compact form)")
    p.add_argument("--verification", type=Path, default=DEFAULT_VERIFICATION,
                   help=f"Path to verification JSON (default {DEFAULT_VERIFICATION.relative_to(REPO_ROOT)})")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="Write Markdown brief to this path (default: stdout)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    data = load_verification(args.verification)
    ops = data.get("ops") or {}

    failing = select_failing(ops, args.tag)
    if not failing:
        sys.exit("No failing ops match the filter.")

    if args.seed is not None:
        random.seed(args.seed)
    pick_n = min(args.count, len(failing))
    picked = random.sample(failing, pick_n)
    picked.sort(key=lambda kv: kv[0])

    out_lines: list[str] = []
    out_lines.append("# Curated-spec triage brief")
    out_lines.append("")
    out_lines.append(f"- Verification source: `{args.verification.relative_to(REPO_ROOT)}`")
    out_lines.append(f"- Generated against base: `{data.get('base_url')}`")
    out_lines.append(f"- Verification run at: `{data.get('generated_at')}`")
    out_lines.append(f"- Total failing ops available: **{len(failing)}**")
    out_lines.append(f"- Sampled this brief: **{pick_n}**" + (f" (seed={args.seed})" if args.seed is not None else ""))
    if args.tag:
        out_lines.append(f"- Tag filter: `{args.tag}`")
    out_lines.append("")
    out_lines.append(FIX_INSTRUCTIONS)
    out_lines.append("")
    out_lines.append("## Cases")
    out_lines.append("")
    for key, op in picked:
        out_lines.append(render_op(key, op))

    if args.include_skipped:
        skipped = select_skipped(ops)
        out_lines.append("## Skipped ops (separate workflow - not random-sampled)")
        out_lines.append("")
        out_lines.append("These were never executed; fixing usually means giving the verifier a")
        out_lines.append("real fixture or removing a documentation-template path.")
        out_lines.append("")
        for key, op in sorted(skipped):
            out_lines.append(render_skipped(key, op))
        out_lines.append("")

    text = "\n".join(out_lines)
    if args.output:
        args.output.write_text(text)
        print(f"Wrote {args.output} ({pick_n} cases, {len(text):,} chars)")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
