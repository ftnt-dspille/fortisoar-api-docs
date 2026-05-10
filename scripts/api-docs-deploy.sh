#!/usr/bin/env bash
# One-shot deploy of the curated docs onto the FortiSOAR appliance.
# Idempotent: safe to re-run after every spec rebuild or index.html edit.
#
# Steps:
#   1. Generate the appliance-tuned index.html (relative spec URL,
#      default server URL = page origin).
#   2. scp index.html + spec to /tmp on the appliance.
#   3. install both into /opt/cyops-ui/api-docs/ as nginx:nginx.
#   4. (first run only) back up cyops-api.conf and insert the
#      `# BEGIN api-docs` location block.
#   5. nginx -t && systemctl reload nginx.
#
# Reads sudo password from
# ~/PycharmProjects/Miscellaneous/fortisoar/.env (SSH_PASSWORD).

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${FSR_SSH_HOST:-fsr}"
ENV_FILE="${HOME}/PycharmProjects/Miscellaneous/fortisoar/.env"

SPEC_LOCAL="$REPO/build/fortisoar.curated.openapi.yaml"
INDEX_SRC="$REPO/web/index.html"
INDEX_BUILT="$REPO/build/appliance/index.html"
SCALAR_LOCAL="$REPO/build/appliance/scalar.js"
SCALAR_URL="https://cdn.jsdelivr.net/npm/@scalar/api-reference"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE (need SSH_PASSWORD=...)" >&2; exit 1
fi
SUDO_PW="$(grep '^SSH_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
[[ -n "$SUDO_PW" ]] || { echo "SSH_PASSWORD not set in $ENV_FILE" >&2; exit 1; }
[[ -f "$SPEC_LOCAL"  ]] || { echo "missing $SPEC_LOCAL - run src/build_curated.py first" >&2; exit 1; }
[[ -f "$INDEX_SRC"   ]] || { echo "missing $INDEX_SRC" >&2; exit 1; }

if [[ ! -f "$SCALAR_LOCAL" ]]; then
  echo "[0/5] Vendoring Scalar bundle (one-time)"
  mkdir -p "$(dirname "$SCALAR_LOCAL")"
  curl -fsSL -o "$SCALAR_LOCAL" "$SCALAR_URL"
fi

remote() {
  ssh -tt "$HOST" "echo $SUDO_PW | sudo -S -p '' bash -c '$*'" 2>&1 \
    | grep -v -E 'ssl_stapling|^\[sudo\]|password for' || true
}

echo "[1/5] Generating appliance index.html"
mkdir -p "$REPO/build/appliance"
# Forced redirect (>|) bypasses zsh noclobber.
sed \
  -e 's|data-url="../build/fortisoar.curated.openapi.yaml"|data-url="/api-docs/spec/fortisoar.openapi.yaml"|' \
  -e "s|'https://fortisoar.example.com'|location.origin|" \
  -e 's|<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>|<script src="scalar.js"></script>|' \
  -e '/<script src="auth\.local\.js"/d' \
  "$INDEX_SRC" >| "$INDEX_BUILT"
grep -q 'data-url="/api-docs/spec/fortisoar.openapi.yaml"' "$INDEX_BUILT" \
  || { echo "sed did not rewrite data-url - aborting" >&2; exit 1; }

echo "[2/5] Copying files to appliance"
scp -q "$INDEX_BUILT"  "$HOST:/tmp/api-docs-index.html"
scp -q "$SPEC_LOCAL"   "$HOST:/tmp/api-docs-spec.yaml"
scp -q "$SCALAR_LOCAL" "$HOST:/tmp/api-docs-scalar.js"

echo "[3/5] Installing into /opt/cyops-ui/api-docs/"
remote "
  mkdir -p /opt/cyops-ui/api-docs/spec
  install -o nginx -g nginx -m 644 /tmp/api-docs-index.html /opt/cyops-ui/api-docs/index.html
  install -o nginx -g nginx -m 644 /tmp/api-docs-spec.yaml  /opt/cyops-ui/api-docs/spec/fortisoar.openapi.yaml
  install -o nginx -g nginx -m 644 /tmp/api-docs-scalar.js  /opt/cyops-ui/api-docs/scalar.js
  chown -R nginx:nginx /opt/cyops-ui/api-docs
  rm -f /tmp/api-docs-index.html /tmp/api-docs-spec.yaml /tmp/api-docs-scalar.js
"

echo "[4/5] Ensuring nginx block + backup"
remote '
  set -e
  if [ ! -f /etc/nginx/conf.d/cyops-api.conf.bak-pre-api-docs ]; then
    cp -p /etc/nginx/conf.d/cyops-api.conf /etc/nginx/conf.d/cyops-api.conf.bak-pre-api-docs
    echo "  backup created"
  else
    echo "  backup already present"
  fi
  if grep -q "BEGIN api-docs" /etc/nginx/conf.d/cyops-api.conf; then
    echo "  api-docs block already inserted"
  else
    python3 - <<PY
from pathlib import Path
import re, sys
p = Path("/etc/nginx/conf.d/cyops-api.conf")
src = p.read_text()
snippet = """
    # BEGIN api-docs
    location /api-docs/ {
        alias /opt/cyops-ui/api-docs/;
        index index.html;
        try_files \$uri \$uri/ /api-docs/index.html;

        types { application/yaml yaml yml; text/html html; }
        default_type application/octet-stream;

        # Override the appliance-wide CSP (which is "default-src self;" -
        # missing quotes around 'self', so it blocks even same-origin
        # scripts). Scalar needs inline + eval for its renderer.
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:;" always;
    }
    # END api-docs
"""
m = list(re.finditer(r"\n\}\s*\Z", src))
if not m: print("could not find end of server block", file=sys.stderr); sys.exit(1)
p.write_text(src[:m[-1].start()] + snippet + src[m[-1].start():])
print("  inserted api-docs block")
PY
  fi
  cp -p /etc/nginx/conf.d/cyops-api.conf /etc/nginx/conf.d/cyops-api.conf.with-api-docs
'

echo "[5/5] nginx -t && systemctl reload nginx"
remote 'nginx -t && systemctl reload nginx && echo "  reload OK"'

echo
echo "Done. Open https://<your-soar>/api-docs/"
echo "Toggle: scripts/api-docs-toggle.sh {status|on|off}"
