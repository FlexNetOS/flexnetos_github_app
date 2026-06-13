# `flexnetos_github_app` bootstrap — automated GitHub App creation

The reproducible, near-zero-touch way to stand up the trusted-writer GitHub App. This replaces the
manual **NEEDS-HUMAN-D** step (hand-create a GitHub App + tunnel) with a scripted flow.

## The one constraint you can't script away

**GitHub has no API to create or install a GitHub App** — it's a deliberate privilege boundary
(you can't mint a repo-writing identity purely programmatically). The sanctioned path is the
**App Manifest flow**, which requires exactly **one authenticated click** ("Create GitHub App")
plus one for install. Everything else — manifest generation, the tunnel, capturing the redirect
`code`, converting it to credentials, and sealing them into envctl — is fully scripted.

To get to **zero clicks**, we drive that click with a headless browser (`auto-approve.mjs`,
playwright) using a browser profile already logged into GitHub as a FlexNetOS org owner. That is
the only way to remove the human, and it's what `--auto-approve` does.

## What gets created and sealed

- A **private** GitHub App on the `FlexNetOS` org named `flexnetos-trusted-writer`, least-privilege:
  `metadata:read, contents:read, checks:write, statuses:write, pull_requests:write`, subscribed to
  `pull_request, push, check_suite, check_run`. It posts a required status check and **never**
  bot-APPROVEs (#25439).
- Sealed into envctl's vault via `secretctl secret add`:
  - `github-app-private-key` — **broker-only** (never revealable; used by `ProviderMint` to sign App-JWTs)
  - `github-app-webhook-secret` — injectable (the server HMACs deliveries with it)
  - `github-app-id`, and `github-app-installation-id` after install

## Prerequisites (one-time)

| Need | Why | Check |
|------|-----|-------|
| `cloudflared` + `cloudflared login` | the webhook tunnel | `cloudflared tunnel list` |
| a domain on your Cloudflare account | named (stable) tunnel hostname | dashboard → your zone |
| `node` 18+ and `npm install` here | the playwright approver | `node -v` |
| `gh auth login` as a FlexNetOS **org owner** | converts the manifest code | `gh auth status` |
| envctl unlocked (`secretctl status`) | sealing the credentials | `secretctl status` |
| a chromium profile logged into GitHub as an org owner | the 0-click browser robot | see below |

Cloudflare account in use: `ad490fa0aa068e418d3e09314c0e01c3` (logged in via personal Google account).

### A logged-in browser profile

`--auto-approve` needs a chromium `user-data-dir` already signed into GitHub as a FlexNetOS org
owner. Create one once:

```bash
# launch a throwaway profile, log into github.com (incl. 2FA), then close it
node -e "import('playwright').then(p=>p.chromium.launchPersistentContext(process.env.P,{headless:false}).then(c=>c.newPage().then(pg=>pg.goto('https://github.com/login'))))" \
  P=$HOME/.fxapp-gh-profile
export FXAPP_BROWSER_PROFILE=$HOME/.fxapp-gh-profile
```

## Run it

```bash
cd scripts/bootstrap && npm install        # first time (installs playwright + chromium)

# Preview the exact manifest + URLs (no browser, no tunnel, no vault):
DRY_RUN=1 ./bootstrap.sh

# Named tunnel, fully hands-off (recommended):
export FXAPP_BROWSER_PROFILE=$HOME/.fxapp-gh-profile
HOSTNAME=app.yourzone.dev ./bootstrap.sh

# Ephemeral tunnel, click once yourself:
AUTO_APPROVE=0 TUNNEL_MODE=quick ./bootstrap.sh
```

Or drive the Rust CLI directly:

```bash
fxapp register --webhook-url https://app.yourzone.dev/webhook \
  --auto-approve --browser-profile "$FXAPP_BROWSER_PROFILE"
fxapp register --webhook-url https://x/webhook --dry-run   # preview only
```

## After bootstrap

1. Start the server behind the tunnel: `FXAPP_WEBHOOK_SECRET=$(…envctl…) fxapp-server` (P3 injects
   the secret via `secretctl run`; the named tunnel already points at `:8787`).
2. The e2e crown slice can now run: PR → webhook → mint token → dispatch → runner → verdict → merge.

## Security notes

- The private key is **broker-only** — it is sealed and used for signing inside envctl; nothing
  prints it. The approver and `gh` never see it (only the manifest `code`, then GitHub returns the
  pem directly into the sealing pipe).
- `auto-approve.mjs` writes **only** a JSON result line to stdout; diagnostics + screenshots
  (`/tmp/fxapp-approver-*.png` on failure) go to stderr.
- The GitHub button selectors are best-effort against GitHub's live DOM; if GitHub changes the
  markup, update the `getByRole`/locator fallbacks in `auto-approve.mjs` (a failure screenshot is
  saved to `/tmp` to help).
- Re-running is safe: the manifest is deterministic; `secretctl secret add --overwrite` backs up on
  overwrite. A second App is only created if you click Create again (GitHub App names are unique).
