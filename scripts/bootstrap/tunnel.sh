#!/usr/bin/env bash
# tunnel.sh — bring up a Cloudflare tunnel to the local fxapp-server, printing the public webhook
# base URL on stdout (everything else goes to stderr) so the bootstrap can capture it.
#
# Two modes:
#   named (default): a stable hostname on a domain in your Cloudflare account. Survives restarts.
#                    Requires: `cloudflared login` done + a zone (domain) on the account.
#   quick (--quick): an ephemeral *.trycloudflare.com URL, zero config, no account/domain needed.
#                    The URL changes every run — fine for one-shot e2e, re-point the App each time.
#
# Env / flags:
#   TUNNEL_NAME   (default: flexnetos-app)
#   HOSTNAME      (named mode, required) e.g. app.example.com  — must be a host on your CF zone
#   LOCAL_URL     (default: http://localhost:8787)  — where fxapp-server listens
#   --quick       use an ephemeral trycloudflare tunnel instead of a named one
#
# Examples:
#   HOSTNAME=app.flexnetos.dev scripts/bootstrap/tunnel.sh         # named, stable
#   scripts/bootstrap/tunnel.sh --quick                            # ephemeral
set -euo pipefail

TUNNEL_NAME="${TUNNEL_NAME:-flexnetos-app}"
LOCAL_URL="${LOCAL_URL:-http://localhost:8787}"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

log() { echo "[tunnel] $*" >&2; }

command -v cloudflared >/dev/null 2>&1 || {
  log "cloudflared not found. Install it:"
  log "  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
  exit 1
}

if [ "$QUICK" = "1" ]; then
  log "starting ephemeral quick tunnel → ${LOCAL_URL} (Ctrl-C to stop)"
  # Quick tunnels print the assigned URL to stderr; tee it and extract the https URL.
  tmp="$(mktemp)"
  cloudflared tunnel --url "${LOCAL_URL}" 2> >(tee "$tmp" >&2) &
  cf_pid=$!
  trap 'kill "$cf_pid" 2>/dev/null || true' EXIT
  for _ in $(seq 1 30); do
    url="$(grep -oE 'https://[a-z0-9.-]+\.trycloudflare\.com' "$tmp" | head -1 || true)"
    [ -n "$url" ] && break
    sleep 1
  done
  [ -n "${url:-}" ] || { log "timed out waiting for the quick-tunnel URL"; exit 1; }
  log "public base URL: ${url}"
  echo "$url"            # stdout: the captured base URL
  wait "$cf_pid"
  exit 0
fi

# Named tunnel.
: "${HOSTNAME:?named mode needs HOSTNAME=<host on your CF zone> (or pass --quick)}"
log "ensuring named tunnel '${TUNNEL_NAME}' exists…"
if ! cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "${TUNNEL_NAME}"; then
  cloudflared tunnel create "${TUNNEL_NAME}" >&2
fi
log "routing DNS ${HOSTNAME} → ${TUNNEL_NAME}…"
cloudflared tunnel route dns "${TUNNEL_NAME}" "${HOSTNAME}" >&2 || \
  log "route dns failed (already routed, or ${HOSTNAME} not on a zone in this account)"
echo "https://${HOSTNAME}"   # stdout: the stable base URL (print before blocking)
log "running tunnel '${TUNNEL_NAME}' → ${LOCAL_URL} (Ctrl-C to stop)"
exec cloudflared tunnel run --url "${LOCAL_URL}" "${TUNNEL_NAME}"
