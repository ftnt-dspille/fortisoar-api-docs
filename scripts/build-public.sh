#!/usr/bin/env bash
# Build a static, read-only docs site for GitHub Pages.
#
# Output:
#   build/public/
#     index.html                       (Test Request hidden, no modal)
#     fortisoar.openapi.yaml           (curated spec, copied alongside)
#
# Differences from the appliance build:
#   - __FSR_DOCS_PUBLIC__ flipped to true -> Scalar's Test Request panel
#     and our server-config modal are both disabled.
#   - data-url points to ./fortisoar.openapi.yaml (relative).
#   - Scalar bundle stays on jsdelivr CDN (CSP is permissive on GH Pages).
#
# Run after src/build_curated.py.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_LOCAL="$REPO/build/fortisoar.curated.openapi.yaml"
INDEX_SRC="$REPO/web/index.html"
OUT_DIR="$REPO/build/public"

[[ -f "$SPEC_LOCAL" ]] || { echo "missing $SPEC_LOCAL - run src/build_curated.py first" >&2; exit 1; }
[[ -f "$INDEX_SRC"  ]] || { echo "missing $INDEX_SRC" >&2; exit 1; }

mkdir -p "$OUT_DIR"

sed \
  -e 's|data-url="../build/fortisoar.curated.openapi.yaml"|data-url="./fortisoar.openapi.yaml"|' \
  -e 's|window.__FSR_DOCS_PUBLIC__ = false;|window.__FSR_DOCS_PUBLIC__ = true;|' \
  "$INDEX_SRC" >| "$OUT_DIR/index.html"

grep -q 'window.__FSR_DOCS_PUBLIC__ = true;' "$OUT_DIR/index.html" \
  || { echo "sed did not flip __FSR_DOCS_PUBLIC__ - aborting" >&2; exit 1; }

cp "$SPEC_LOCAL" "$OUT_DIR/fortisoar.openapi.yaml"

echo "Public build at $OUT_DIR/"
echo "  serve locally:  python3 -m http.server -d $OUT_DIR 8080"
