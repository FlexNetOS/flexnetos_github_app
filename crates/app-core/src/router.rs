//! Event router (ADR-0008 §1) + protected-files denylist (separation of privilege, §5).
//!
//! Maps an already-signature-verified webhook event to a local [`Dispatch`] for
//! `flexnetos_runner`. The runner is delegate-only (routes to loop_lib/atc/handoff/weave);
//! this module decides *what* to dispatch, never *how* to execute. P0 routes a
//! representative subset; the signed dispatch envelope (S7) is wired in P2.

use crate::webhook::EventKind;

/// A local job dispatched to `flexnetos_runner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    /// Build/test a ref (runner → loop_lib fan-out).
    Ci { repo: String, head_sha: String },
    /// Run the merge-gate review for a PR (runner/atc → verdict check-run).
    ReviewGate {
        repo: String,
        pr_number: u64,
        head_sha: String,
    },
    /// No action for this event.
    Ignore,
}

/// Minimal routing context extracted from the verified payload (the server parses the
/// JSON body into this; kept tiny so routing is pure and testable).
#[derive(Debug, Clone)]
pub struct EventContext {
    pub kind: EventKind,
    pub repo: String,
    pub action: Option<String>,
    pub pr_number: Option<u64>,
    pub head_sha: Option<String>,
}

/// Route a verified event to a dispatch. Pure.
pub fn route(ctx: &EventContext) -> Dispatch {
    match (&ctx.kind, ctx.action.as_deref()) {
        (
            EventKind::PullRequest,
            Some("opened" | "synchronize" | "reopened" | "ready_for_review"),
        ) => match (ctx.pr_number, &ctx.head_sha) {
            (Some(pr), Some(sha)) => Dispatch::ReviewGate {
                repo: ctx.repo.clone(),
                pr_number: pr,
                head_sha: sha.clone(),
            },
            _ => Dispatch::Ignore,
        },
        (EventKind::Push, _) => match &ctx.head_sha {
            Some(sha) => Dispatch::Ci {
                repo: ctx.repo.clone(),
                head_sha: sha.clone(),
            },
            None => Dispatch::Ignore,
        },
        _ => Dispatch::Ignore,
    }
}

/// Build an [`EventContext`] from a parsed webhook payload and its event kind. Tolerant:
/// any missing field becomes `None`, which routes to [`Dispatch::Ignore`] rather than panics.
pub fn event_context_from_payload(kind: EventKind, payload: &serde_json::Value) -> EventContext {
    let repo = payload
        .pointer("/repository/full_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .map(String::from);
    let pr_number = payload
        .pointer("/pull_request/number")
        .and_then(|v| v.as_u64());
    let head_sha = match &kind {
        EventKind::PullRequest => payload
            .pointer("/pull_request/head/sha")
            .and_then(|v| v.as_str())
            .map(String::from),
        EventKind::Push => payload
            .get("after")
            .and_then(|v| v.as_str())
            .map(String::from),
        _ => None,
    };
    EventContext {
        kind,
        repo,
        action,
        pr_number,
        head_sha,
    }
}

/// Whether a pull-request payload originates from a fork — the signal that drives the runner's
/// fork-PR isolation (ADR-0008 §6). The reliable cross-repo test is head-repo ≠ base-repo.
/// **Fails safe:** a non-PR payload is `false`; a PR with an absent head repo (e.g. the fork was
/// deleted) is treated as `true` (untrusted) so it can never be mistaken for a trusted same-repo PR.
pub fn payload_is_from_fork(payload: &serde_json::Value) -> bool {
    let pr = match payload.get("pull_request") {
        Some(p) => p,
        None => return false,
    };
    let head = pr.pointer("/head/repo/full_name").and_then(|v| v.as_str());
    let base = pr.pointer("/base/repo/full_name").and_then(|v| v.as_str());
    match (head, base) {
        (Some(h), Some(b)) => h != b,
        _ => true,
    }
}

/// Protected-files denylist (ADR-0008 §5): a privileged write touching any of these
/// must be refused / threat-scanned before the trusted writer acts. Conservative match.
pub fn is_protected(path: &str) -> bool {
    let p = path.trim_start_matches("./");
    p.starts_with(".github/")
        || p == "CLAUDE.md"
        || p.ends_with("/CLAUDE.md")
        || p == ".meta.yaml"
        || p.ends_with("/.meta.yaml")
        || p == "Cargo.lock"
        || p.ends_with("/agent-env.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        kind: EventKind,
        action: Option<&str>,
        pr: Option<u64>,
        sha: Option<&str>,
    ) -> EventContext {
        EventContext {
            kind,
            repo: "FlexNetOS/x".into(),
            action: action.map(String::from),
            pr_number: pr,
            head_sha: sha.map(String::from),
        }
    }

    #[test]
    fn pr_opened_routes_to_review_gate() {
        let d = route(&ctx(
            EventKind::PullRequest,
            Some("opened"),
            Some(7),
            Some("deadbeef"),
        ));
        assert_eq!(
            d,
            Dispatch::ReviewGate {
                repo: "FlexNetOS/x".into(),
                pr_number: 7,
                head_sha: "deadbeef".into(),
            }
        );
    }

    #[test]
    fn push_routes_to_ci() {
        assert_eq!(
            route(&ctx(EventKind::Push, None, None, Some("cafe"))),
            Dispatch::Ci {
                repo: "FlexNetOS/x".into(),
                head_sha: "cafe".into(),
            }
        );
    }

    #[test]
    fn unrelated_events_are_ignored() {
        assert_eq!(
            route(&ctx(EventKind::Ping, None, None, None)),
            Dispatch::Ignore
        );
        assert_eq!(
            route(&ctx(
                EventKind::PullRequest,
                Some("labeled"),
                Some(7),
                Some("x")
            )),
            Dispatch::Ignore
        );
    }

    #[test]
    fn protected_files_denylist() {
        assert!(is_protected(".github/workflows/ci.yml"));
        assert!(is_protected("CLAUDE.md"));
        assert!(is_protected("sub/dir/CLAUDE.md"));
        assert!(is_protected(".meta.yaml"));
        assert!(!is_protected("src/main.rs"));
        assert!(!is_protected("README.md"));
    }

    #[test]
    fn pr_payload_parses_into_review_gate_context() {
        let payload = serde_json::json!({
            "action": "opened",
            "repository": { "full_name": "FlexNetOS/x" },
            "pull_request": { "number": 7, "head": { "sha": "deadbeef" } },
        });
        let ctx = event_context_from_payload(EventKind::PullRequest, &payload);
        assert_eq!(
            route(&ctx),
            Dispatch::ReviewGate {
                repo: "FlexNetOS/x".into(),
                pr_number: 7,
                head_sha: "deadbeef".into(),
            }
        );
    }

    #[test]
    fn push_payload_parses_into_ci_context() {
        let payload = serde_json::json!({
            "repository": { "full_name": "FlexNetOS/x" },
            "after": "cafef00d",
        });
        let ctx = event_context_from_payload(EventKind::Push, &payload);
        assert_eq!(
            route(&ctx),
            Dispatch::Ci {
                repo: "FlexNetOS/x".into(),
                head_sha: "cafef00d".into(),
            }
        );
    }

    #[test]
    fn missing_fields_route_to_ignore_not_panic() {
        let ctx = event_context_from_payload(EventKind::PullRequest, &serde_json::json!({}));
        assert_eq!(route(&ctx), Dispatch::Ignore);
    }

    #[test]
    fn from_fork_detects_cross_repo_and_fails_safe() {
        let same = serde_json::json!({
            "pull_request": {
                "head": { "repo": { "full_name": "FlexNetOS/x" } },
                "base": { "repo": { "full_name": "FlexNetOS/x" } },
            }
        });
        let cross = serde_json::json!({
            "pull_request": {
                "head": { "repo": { "full_name": "attacker/x" } },
                "base": { "repo": { "full_name": "FlexNetOS/x" } },
            }
        });
        let deleted_fork = serde_json::json!({
            "pull_request": { "base": { "repo": { "full_name": "FlexNetOS/x" } } }
        });
        assert!(!payload_is_from_fork(&same));
        assert!(payload_is_from_fork(&cross));
        assert!(payload_is_from_fork(&deleted_fork)); // fails safe
        assert!(!payload_is_from_fork(&serde_json::json!({}))); // non-PR
    }
}
