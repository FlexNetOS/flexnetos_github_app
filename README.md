# flexnetos_github_app

The **control plane** of FlexNetOS's GitHub↔local automation: a self-hosted **GitHub App** that
is the org's privilege-separated identity, event ingress, and trusted writer. It receives webhooks
from every FlexNetOS repo, mints short-lived per-repo installation tokens (the App private key is
sealed in **envctl**'s vault — never in this process), and executes the merge-gate by posting the
AI-gatekeeper verdict as a **required status check** (never a bot-APPROVE). It dispatches work to
[`flexnetos_runner`](https://github.com/FlexNetOS/flexnetos_runner) for local execution.

Design: **ADR-0008** (`handoff/docs/adr-0008-flexnetos-app-runner.md`). It replaces the long-lived
`PARENT_REPO_PAT` and is the concrete home for ADR-0001 §5a's "separate scoped-write job".

## Workspace

| Crate | Bin | Role |
|-------|-----|------|
| `app-core` | — | Pure core: webhook HMAC verify, App-JWT claims, envctl token-mint seam, merge-gate executor, event router, protected-files denylist. Non-printing, fully unit-tested. |
| `app-server` | `fxapp-server` | axum webhook ingress (`POST /webhook`, `/health`); verifies `X-Hub-Signature-256` and (P2) routes to the runner. Runs locally behind a tunnel. |
| `app-cli` | `fxapp` | Operator CLI: `sign`, `verify`, `doctor`. |

## Status — P0 (scaffold)

Implemented and tested: webhook signature verification (constant-time HMAC-SHA256), App-JWT claim
construction (RS256, `exp ≤ 10m`, `iat −60s`), event routing, protected-files denylist, redacted
token type. The envctl token-mint (P1), live webhook routing/dispatch (P2), and the GitHub
check-runs/auto-merge merge-gate (P3) are typed seams that currently **fail closed**.

## Build

```bash
cargo build --workspace
cargo test  --workspace          # all core invariants
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
fxapp doctor
```

## Security posture

Short-lived (≤1h GitHub / ≤24h envctl) per-repo, per-permission installation tokens; constant-time
webhook verification; **no credential custody** (envctl vault is the sole keystore); separation of
privilege (the app is the scoped writer, not the reviewer/judge); merge verdict via check-run only.
Deploys **local + tunnel** (no public listener; no VPS). See ADR-0008 §6.
