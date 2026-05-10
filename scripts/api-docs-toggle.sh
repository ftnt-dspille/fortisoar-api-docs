#!/usr/bin/env bash
# Quick on/off toggle for the api-docs nginx block on the FortiSOAR
# appliance. Reads the sudo password from
# ~/PycharmProjects/Miscellaneous/fortisoar/.env (SSH_PASSWORD).
#
# Usage:
#   scripts/api-docs-toggle.sh status      # which version is live?
#   scripts/api-docs-toggle.sh off         # restore backup, reload
#   scripts/api-docs-toggle.sh on          # restore patched, reload
#
# `off` and `on` are O(1): they just swap two pre-staged files on the
# appliance and reload nginx. No sed, no rebuild.

set -euo pipefail

HOST="${FSR_SSH_HOST:-fsr}"
ENV_FILE="${HOME}/PycharmProjects/Miscellaneous/fortisoar/.env"
CONF=/etc/nginx/conf.d/cyops-api.conf
BAK=/etc/nginx/conf.d/cyops-api.conf.bak-pre-api-docs
PATCHED=/etc/nginx/conf.d/cyops-api.conf.with-api-docs

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE (need SSH_PASSWORD=...)" >&2
  exit 1
fi
SUDO_PW="$(grep '^SSH_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
if [[ -z "$SUDO_PW" ]]; then
  echo "SSH_PASSWORD not set in $ENV_FILE" >&2
  exit 1
fi

remote() {
  ssh -tt "$HOST" "echo $SUDO_PW | sudo -S -p '' bash -c '$*'" 2>&1 \
    | grep -v -E 'ssl_stapling|^\[sudo\]|password for' || true
}

case "${1:-status}" in
  status)
    remote '
      if [ ! -f '"$BAK"' ]; then
        echo "no backup found - api-docs has never been installed"
        exit 0
      fi
      if [ ! -f '"$PATCHED"' ]; then
        cp -p '"$CONF"' '"$PATCHED"'
      fi
      if cmp -s '"$CONF"' '"$BAK"'; then
        echo "live: ORIGINAL (api-docs OFF)"
      elif cmp -s '"$CONF"' '"$PATCHED"'; then
        echo "live: PATCHED (api-docs ON)"
      else
        echo "live: UNKNOWN (cyops-api.conf differs from both backup and patched)"
      fi
    '
    ;;
  off)
    remote '
      if [ ! -f '"$BAK"' ]; then
        echo "ERROR: no backup at '"$BAK"'" >&2; exit 1
      fi
      # Stash current as patched copy first time we toggle off.
      [ -f '"$PATCHED"' ] || cp -p '"$CONF"' '"$PATCHED"'
      cp -p '"$BAK"' '"$CONF"'
      nginx -t && systemctl reload nginx && echo "api-docs OFF (original config live)"
    '
    ;;
  on)
    remote '
      if [ ! -f '"$PATCHED"' ]; then
        echo "ERROR: no patched copy at '"$PATCHED"' - run setup first" >&2; exit 1
      fi
      cp -p '"$PATCHED"' '"$CONF"'
      nginx -t && systemctl reload nginx && echo "api-docs ON (patched config live)"
    '
    ;;
  *)
    echo "usage: $0 {status|on|off}" >&2; exit 2;;
esac
