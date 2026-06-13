#!/usr/bin/env bash
# bootstrap.sh — one command to stand up the trusted-writer GitHub App, end to end.
#
# Flow: preflight → bring up the cloudflared tunnel → `fxapp register` (manifest flow → browser
# robot clicks Create + Install → `gh api` converts the code → envctl seals the key/secret).
#
# This is the reproducible, near-zero-touch replacement for the manual NEEDS-HUMAN-D step. With a
# logged-in browser profile + --auto-approve it is fully hands-off; otherwise you click once.
#
# Required env:
#   FXAPP_BROWSER_PROFILE   chromium user-data-dir logged into GitHub as a FlexNetOS org owner
# Optional env:
#   ORG (FlexNetOS) · APP_NAME (flexnetos-trusted-writer) · HOSTNAME (named tunnel host)
#   TUNNEL_MODE (named|quick, default named if HOSTNAME set else quick) · LOCAL_URL (http://localhost:8787)
#   AUTO_APPROVE (1)  · DRY_RUN (0)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
log() { echo "[bootstrap] $*" >&2; }

ORG="${ORG:-FlexNetOS}"
APP_NAME="${APP_NAME:-flexnetos-trusted-writer}"
LOCAL_URL="${LOCAL_URL:-http://localhost:8787}"
AUTO_APPROVE="${AUTO_APPROVE:-1}"
DRY_RUN="${DRY_RUN:-0}"
TUNNEL_MODE="${TUNNEL_MODE:-$([ -n "${HOSTNAME:-}" ] && echo named || echo quick)}"
# Playwright has no bundled chromium on some OSes (e.g. ubuntu 26.04); drive a system browser.
# Default to system Chrome; set BROWSER_CHANNEL="" to use playwright's bundled chromium instead.
BROWSER_CHANNEL="${BROWSER_CHANNEL:-chrome}"

# ---- preflight ---------------------------------------------------------------
log "preflight…"
need() { command -v "$1" >/dev/null 2>&1 || { log "MISSING: $1 — $2"; exit 1; }; }
need cloudflared "install from Cloudflare; run 'cloudflared login' once"
need node        "install Node 18+"
need gh          "GitHub CLI; run 'gh auth login' as a FlexNetOS org owner"
need cargo       "Rust toolchain"
gh auth status >/dev/null 2>&1 || { log "gh not authenticated (gh auth login)"; exit 1; }
if [ "$DRY_RUN" != "1" ] && [ "$AUTO_APPROVE" = "1" ] && [ -z "${FXAPP_BROWSER_PROFILE:-}" ]; then
  log "FXAPP_BROWSER_PROFILE is required for --auto-approve (a logged-in chromium profile)."
  log "Set it, or run with AUTO_APPROVE=0 to click once in a window, or DRY_RUN=1 to preview."
  exit 1
fi
[ -d "$here/node_modules/playwright" ] || { log "installing playwright…"; (cd "$here" && npm install >&2); }

# ---- dry run short-circuit ---------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  log "DRY_RUN: previewing manifest only (no tunnel, no browser, no vault)"
  cargo run -q --manifest-path "$repo/Cargo.toml" -p app-cli -- \
    register --org "$ORG" --name "$APP_NAME" --webhook-url "https://example.invalid/webhook" --dry-run
  exit 0
fi

# ---- tunnel up ---------------------------------------------------------------
log "starting ${TUNNEL_MODE} tunnel…"
tunnel_out="$(mktemp)"
if [ "$TUNNEL_MODE" = "quick" ]; then
  LOCAL_URL="$LOCAL_URL" "$here/tunnel.sh" --quick > "$tunnel_out" &
else
  HOSTNAME="${HOSTNAME:?named tunnel needs HOSTNAME}" LOCAL_URL="$LOCAL_URL" "$here/tunnel.sh" > "$tunnel_out" &
fi
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do BASE="$(head -1 "$tunnel_out" 2>/dev/null || true)"; [ -n "$BASE" ] && break; sleep 1; done
[ -n "${BASE:-}" ] || { log "no tunnel URL captured"; exit 1; }
WEBHOOK_URL="${BASE%/}/webhook"
log "webhook URL: ${WEBHOOK_URL}"

# ---- register ----------------------------------------------------------------
log "registering the App (auto_approve=${AUTO_APPROVE})…"
args=(register --org "$ORG" --name "$APP_NAME" --webhook-url "$WEBHOOK_URL"
      --approver "$here/auto-approve.mjs")
[ -n "$BROWSER_CHANNEL" ] && args+=(--browser-channel "$BROWSER_CHANNEL")
[ "$AUTO_APPROVE" = "1" ] && args+=(--auto-approve --browser-profile "${FXAPP_BROWSER_PROFILE}")
cargo run -q --manifest-path "$repo/Cargo.toml" -p app-cli -- "${args[@]}"
log "done. The App private key + webhook secret are sealed in envctl; start fxapp-server behind the tunnel."
