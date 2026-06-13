# HANDOFF — FlexNetOS GitHub trusted-writer stack (2026-06-13)

Cold-start checkpoint for the two-plane GitHub integration (ADR-0007/0008): **flexnetos_github_app**
(control plane) + **flexnetos_runner** (execution plane), bound by **envctl** (secrets/mint).
State precedence: **Git > ledger > cards > prose** (this file is prose — verify against Git).

## TL;DR — where it stands

The App is **created, installed, sealed, and live**. The webhook→dispatch→fork-gate chain is
**proven live** through a public tunnel with the real sealed secret. The token **write-back**
(mint installation token → post check-run) is **not yet wired** — it's the main remaining slice,
blocked only on the envctl mint surface which is **carded (envctl TASK-0020, merged to develop)**.

## DONE + verified (with evidence)

- **GitHub App live** — org-owned **@FlexNetOS**, app_id **4044997**, slug `flexnetos-github-app`,
  installation **140063898**, repo_selection=all. Verified `app↔installation↔org` via
  `gh api /orgs/FlexNetOS/installations`.
- **Vault (envctl, Seed-unlocked)** holds 5 sealed secrets: `github-app-private-key` (**broker-only**,
  PKCS#1, the downloaded `.pem` was shredded), `github-app-webhook-secret`, `github-app-id`,
  `github-app-client-id`, `github-app-installation-id`.
- **Merged PRs** — flexnetos_github_app: #1 (P1 EnvctlMinter), #2 (P2 dispatch), #3 (bootstrap),
  #4 (chrome-channel). flexnetos_runner: #2 (P2 UDS dispatch). envctl: #35 (ProviderMint github),
  #65 (TASK-0020 build-ready card).
- **Live e2e (control→execution) PROVEN** through the public Cloudflare quick tunnel with the real
  webhook secret: valid same-repo PR → routed → signed JobSpec over UDS → runner verify →
  fork-gate → delegate to `atc`; **fork PR (head≠base) → runner REJECTED, never delegated**;
  bad signature → `401`; push → `loop`; ping → ignored; non-JSON body → graceful 202+log.
  During the test the **real installed App delivered real org events** (workflow_job, pushes,
  PR #67) through the tunnel and the runner delegated them — unplanned proof the live App works.

## Verify-on-resume baseline (run FIRST; fail → triage before building)

```bash
# app + runner build/test/clippy (from each repo's main)
cd ~/Desktop/meta/flexnetos_github_app && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --all -- --check
cd ~/Desktop/meta/flexnetos_runner   && cargo test   # NOTE: P2 UDS lives on main via #2; primary checkout may be on a feature branch — use origin/main
# vault must be unlocked (Seed) before any mint/seal work
secretctl status            # expect: unlocked
# confirm the live App identity
gh api /orgs/FlexNetOS/installations --jq '.installations[]|select(.id==140063898)|{app_id,app_slug,target}'
```

## Remaining work — gap-hunt (`/verify` 2026-06-13), classified + routed

| # | Sev | Item | Lands in |
|---|---|---|---|
| 1 | feature | **P3 merge-gate executor** — `merge_gate.rs` exists but `app-server` never posts a check-run (the trusted-writer's purpose: verdict = required status check, never bot-APPROVE) | flexnetos_github_app PR (P3) |
| 2 | feature | Runner only `DryRunInvoker` — wire a real `KernelInvoker` (loop_lib/atc/hf) + envctl secret injection | flexnetos_runner PR (P3) |
| 3 | feature | **mint→write-back unwired** — after TASK-0020 lands, `app-server` must mint a token + post the check-run | flexnetos_github_app PR (P3; deps envctl TASK-0020) |
| 4 | harden | No `X-GitHub-Delivery` dedup → GitHub redelivery double-dispatches | flexnetos_github_app PR |
| 5 | harden | Webhook secret read from plaintext env — inject via envctl (`env-ctl run` auto-inject seam, now COMPLETE per envctl #51/#58/#60/#63/#69) instead | flexnetos_github_app (P3) |
| 6 | harden | **Ephemeral-tunnel fragility** — App webhook URL is a `trycloudflare.com` quick tunnel; needs a **named tunnel + `fxapp-server` as a managed service** (App is live → real deliveries 502 when the dev server stops) | ops (envctl component / runbook) |
| 7 | feature | `runner-actions` is a 34-line P0 stub — JIT self-hosted Actions supervisor (generate-jitconfig→agent→single-job→deregister) | flexnetos_runner PR (P1) |
| 8 | upgrade | `fxapp replay <payload.json>` + `install-smoke` missing (plan listed them) — `replay` makes offline e2e first-class | flexnetos_github_app (small) |
| 9 | harden | **App over-privileged + broad events** — confirmed firing live on workflow_job etc. across all repos. Tighten to 5 scopes (metadata:read, contents:read, checks/statuses/pull_requests:write) + 4 events | **owner action — DEFERRED until runner+stack complete** |

**Next-PR grouping:** app gets #1+#3+#4 (the P3 write-back slice) + #5/#8; runner gets #2 + #7.
envctl mint surface (#3's dependency) = TASK-0020 (the forge loop builds it).

## Open decisions for the resumer / owner

- **Live test processes still running** (this session): `fxapp-server` (:8787), `fxrun-dispatch`
  (UDS `/tmp/fxrun-e2e.sock`), and the quick tunnel `singing-direct-folks-belongs.trycloudflare.com`
  (= the App's current webhook URL). They consume real org webhooks until stopped. **Decide:**
  tear down (clean) **or** replace with a persistent named-tunnel service (#6) before they're useful.
- **App permission tightening (#9)** — deferred by owner until the runner + full GitHub stack are done.

## Pointers

- ICM topic `context-flexnetos` (App identity, sealed secrets, gap-hunt, decisions); errors-resolved
  (windows-cfg, daemon-restore). Memories: `github-app-no-create-api`, `envctl-secretd-daemon-handsoff`,
  `always-auto-merge`, `run-verify-when-slow`.
- envctl forge-loop backlog: **TASK-0020 (github-app-mint)** — the build-ready card for `secretctl
  mint-github` (frozen CLI contract `{token, expires_at_unix}`; reuse the #58 reqwest/webpki-roots
  transport; LIVE acceptance data inline).
- ADRs: ADR-0007 (app+runner two-plane), ADR-0008 (architecture/§B manifest flow, §5 separation of
  privilege, §6 fork isolation). Bootstrap runbook: `scripts/bootstrap/README.md`.

## Lessons (this session)

- GitHub has **no API to create/install an App** — manifest flow needs 1 browser click; 0-click =
  playwright robot (`scripts/bootstrap/`). No browser/computer-use MCP in Claude sessions here.
- **Do not unilaterally restart/rebuild `env-ctl.service`** — owner-developed; needs `--features
  seed-factor`; Seed unlocks it (no passphrase). (Broke + restored it once this session.)
- When a task drags, **run `/verify`** to gap-hunt + propose upgrades (this file's table is that output).
