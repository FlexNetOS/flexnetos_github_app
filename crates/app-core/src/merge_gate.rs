//! Merge-gate executor (ADR-0008 §1/S4). Posts the gatekeeper verdict as a GitHub
//! **check-run** (wired as a *required status check*) and arms native auto-merge — but
//! only **after** the verdict is green, structurally avoiding the ~2026-03 HTTP-422
//! "requirements not yet satisfied" behavior (ADR-0008 §B). It is **never** a native
//! `github-actions[bot]` APPROVE (bypasses branch protection, #25439).
//!
//! Like [`crate::mint`], this layer performs no network I/O directly: it shells the **`gh`
//! CLI** through the [`GithubInvoker`] seam (mirroring `mint`'s [`crate::mint::MintInvoker`]).
//! The production [`GhCliInvoker`] runs `gh api`, authenticating via the short-lived
//! installation token minted by envctl — passed to the child process through the `GH_TOKEN`
//! environment variable, **never** on argv (tokens must not appear in the process list/logs).
//! [`UnwiredMergeGate`] remains the explicit fail-closed default until a gate is wired.

use crate::mint::ScopedToken;
use thiserror::Error;

/// The GitHub check-run conclusion subset we emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conclusion {
    Success,
    Failure,
    Neutral,
    ActionRequired,
}

impl Conclusion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::ActionRequired => "action_required",
        }
    }
    /// Whether this verdict permits arming auto-merge.
    pub fn is_green(&self) -> bool {
        matches!(self, Self::Success)
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub head_sha: String,
    pub check_name: String,
    pub conclusion: Conclusion,
    pub summary: String,
}

#[derive(Debug, Error)]
pub enum MergeGateError {
    #[error("auto-merge cannot be armed until all requirements pass (HTTP 422)")]
    RequirementsNotMet,
    #[error("github api: {0}")]
    Api(String),
    #[error("refused: verdict not green ({0})")]
    NotGreen(&'static str),
    #[error("not yet wired ({0})")]
    NotWired(&'static str),
}

/// The executor the app drives. Implementations post the verdict check-run and, only
/// when green, arm auto-merge.
pub trait MergeGate: Send + Sync {
    /// Create/update the verdict check-run. MUST be a check-run, never an APPROVE.
    fn post_verdict(&self, verdict: &Verdict) -> Result<(), MergeGateError>;
    /// Arm GitHub-native auto-merge for the PR. Implementations MUST treat an early
    /// `HTTP 422` as [`MergeGateError::RequirementsNotMet`] and not crash.
    fn arm_auto_merge(&self, pr_number: u64) -> Result<(), MergeGateError>;
}

/// Guard enforcing "post a green verdict before arming auto-merge" (the 422-avoidance
/// rule). Returns `Ok(())` only when the verdict is green.
pub fn ensure_armable(verdict: &Verdict) -> Result<(), MergeGateError> {
    if verdict.conclusion.is_green() {
        Ok(())
    } else {
        Err(MergeGateError::NotGreen(
            "auto-merge may be armed only after a success verdict",
        ))
    }
}

/// P0 placeholder: fails closed until the GitHub check-runs/auto-merge client lands (P3).
#[derive(Default)]
pub struct UnwiredMergeGate;

impl MergeGate for UnwiredMergeGate {
    fn post_verdict(&self, _verdict: &Verdict) -> Result<(), MergeGateError> {
        Err(MergeGateError::NotWired("check-runs API — P3"))
    }
    fn arm_auto_merge(&self, _pr_number: u64) -> Result<(), MergeGateError> {
        Err(MergeGateError::NotWired("auto-merge — P3"))
    }
}

/// The seam to GitHub (mirrors [`crate::mint::MintInvoker`]). The production [`GhCliInvoker`]
/// shells `gh api`; tests inject a fake so the request/parse contract is proven without a live
/// GitHub. The minted installation token is supplied out-of-band and set on the child's
/// `GH_TOKEN` env var — it is **never** passed through `argv`. Returns raw stdout on success or a
/// transport error string (non-zero exit / spawn failure), with stderr surfaced so an early
/// HTTP-422 can be detected.
pub trait GithubInvoker: Send + Sync {
    /// Run `gh` with the given argv, authenticating the child via `GH_TOKEN=token`.
    /// The `token` MUST NOT be logged or placed into `argv`.
    fn invoke(&self, token: &str, argv: &[String]) -> Result<Vec<u8>, String>;
}

/// The wired [`MergeGate`] (P3): delegates to GitHub through a [`GithubInvoker`]. The caller mints
/// the short-lived installation token via envctl (`EnvctlMinter`) and constructs the gate per
/// request. The token never enters argv/logs — only the child's `GH_TOKEN`. Generic over the
/// invoker so the gh path is exercised with a fake (no live GitHub) in tests.
pub struct GithubMergeGate<I: GithubInvoker> {
    invoker: I,
    owner: String,
    repo: String,
    token: ScopedToken,
}

impl<I: GithubInvoker> GithubMergeGate<I> {
    /// Build a per-request gate. `token` is the envctl-minted installation token (held as a
    /// redacted [`ScopedToken`]; only reachable via `.expose()` and never logged).
    pub fn new(
        invoker: I,
        owner: impl Into<String>,
        repo: impl Into<String>,
        token: ScopedToken,
    ) -> Self {
        Self {
            invoker,
            owner: owner.into(),
            repo: repo.into(),
            token,
        }
    }
}

impl<I: GithubInvoker> MergeGate for GithubMergeGate<I> {
    fn post_verdict(&self, verdict: &Verdict) -> Result<(), MergeGateError> {
        let argv = build_check_run_argv(&self.owner, &self.repo, verdict);
        self.invoker
            .invoke(self.token.expose(), &argv)
            .map_err(MergeGateError::Api)?;
        Ok(())
    }

    /// Arm auto-merge as a genuine two-step: (1) resolve the PR's GraphQL **node id**
    /// (`enablePullRequestAutoMerge` needs the id, not the number — and a single
    /// `gh api graphql` call executes only ONE document, so resolve-then-mutate cannot be
    /// fused), then (2) run the enable-auto-merge mutation with that id. An early HTTP-422
    /// in either step maps to [`MergeGateError::RequirementsNotMet`]; everything else (and a
    /// missing node id) fails closed as [`MergeGateError::Api`].
    fn arm_auto_merge(&self, pr_number: u64) -> Result<(), MergeGateError> {
        // Step 1: resolve the PR node id.
        let resolve_argv = build_resolve_pr_node_id_argv(&self.owner, &self.repo, pr_number);
        let resolve_out = self
            .invoker
            .invoke(self.token.expose(), &resolve_argv)
            .map_err(map_invoke_err)?;
        let node_id = parse_pr_node_id(&resolve_out)
            .ok_or_else(|| MergeGateError::Api("could not resolve PR node id".to_string()))?;

        // Step 2: enable auto-merge using the resolved node id.
        let enable_argv = build_enable_auto_merge_argv(&node_id);
        self.invoker
            .invoke(self.token.expose(), &enable_argv)
            .map_err(map_invoke_err)?;
        Ok(())
    }
}

/// Map a `gh` transport error to the right [`MergeGateError`]: an early HTTP-422
/// ("requirements not yet satisfied") becomes [`MergeGateError::RequirementsNotMet`]; any other
/// failure fails closed as [`MergeGateError::Api`].
fn map_invoke_err(e: String) -> MergeGateError {
    if is_requirements_not_met(&e) {
        MergeGateError::RequirementsNotMet
    } else {
        MergeGateError::Api(e)
    }
}

/// Parse the PR GraphQL node id out of the resolve-step response
/// (`data.repository.pullRequest.id`). Returns `None` if the shape is missing/unexpected.
fn parse_pr_node_id(stdout: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    v.get("data")?
        .get("repository")?
        .get("pullRequest")?
        .get("id")?
        .as_str()
        .map(|s| s.to_string())
}

/// Detect GitHub's early "requirements not yet satisfied" rejection (HTTP 422) in a `gh`
/// transport error string, so it maps to [`MergeGateError::RequirementsNotMet`] rather than a
/// generic API error (ADR-0008 §B).
fn is_requirements_not_met(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("422") || e.contains("requirements") || e.contains("not yet satisfied")
}

/// The argv for the verdict check-run (pure; unit-tested so the wire contract is pinned
/// independently of process execution). Builds:
/// `gh api --method POST /repos/{owner}/{repo}/check-runs -f name=… -f head_sha=…
/// -f status=completed -f conclusion=… -f output[title]=… -f output[summary]=…`.
/// The token is **never** included here — the invoker sets it as `GH_TOKEN` on the child.
pub fn build_check_run_argv(owner: &str, repo: &str, verdict: &Verdict) -> Vec<String> {
    vec![
        "api".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        format!("/repos/{owner}/{repo}/check-runs"),
        "-f".to_string(),
        format!("name={}", verdict.check_name),
        "-f".to_string(),
        format!("head_sha={}", verdict.head_sha),
        "-f".to_string(),
        "status=completed".to_string(),
        "-f".to_string(),
        format!("conclusion={}", verdict.conclusion.as_str()),
        "-f".to_string(),
        format!("output[title]={}", verdict.check_name),
        "-f".to_string(),
        format!("output[summary]={}", verdict.summary),
    ]
}

/// Step 1 of arming auto-merge: the argv that resolves a PR's GraphQL **node id** from its number
/// (pure; unit-tested). `enablePullRequestAutoMerge` accepts only the node id, and a single
/// `gh api graphql` call runs exactly one GraphQL document — so the resolve must be its own call.
/// Builds `gh api graphql -f query='…pullRequest(number:$pr){id}…' -F owner=… -F repo=… -F pr=…`,
/// passing `-F pr=` so the variable is typed as the `Int!` the query declares. The token is
/// **never** in argv.
pub fn build_resolve_pr_node_id_argv(owner: &str, repo: &str, pr_number: u64) -> Vec<String> {
    let query = "\
query($owner:String!,$repo:String!,$pr:Int!){repository(owner:$owner,name:$repo){\
pullRequest(number:$pr){id}}}";
    vec![
        "api".to_string(),
        "graphql".to_string(),
        "-f".to_string(),
        format!("query={query}"),
        "-F".to_string(),
        format!("owner={owner}"),
        "-F".to_string(),
        format!("repo={repo}"),
        "-F".to_string(),
        format!("pr={pr_number}"),
    ]
}

/// Step 2 of arming auto-merge: the argv for the `enablePullRequestAutoMerge` mutation (squash),
/// given the PR node id resolved in step 1 (pure; unit-tested). It is **never** a
/// `github-actions[bot]` APPROVE, which would bypass branch protection (#25439). The mutation
/// document is still passed in the `query` field — that is how `gh api graphql` accepts any
/// operation. The token is **never** in argv.
pub fn build_enable_auto_merge_argv(node_id: &str) -> Vec<String> {
    let mutation = "\
mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,\
mergeMethod:SQUASH}){pullRequest{autoMergeRequest{enabledAt}}}}";
    vec![
        "api".to_string(),
        "graphql".to_string(),
        "-f".to_string(),
        format!("query={mutation}"),
        "-F".to_string(),
        format!("id={node_id}"),
    ]
}

/// Production [`GithubInvoker`]: shells `gh api`, authenticating the child via `GH_TOKEN` (never
/// argv). `gh` talks to the GitHub REST/GraphQL API with the envctl-minted installation token, so
/// no plaintext PAT is ever used (fail-closed; ADR-0008 risk note). A non-zero exit becomes the
/// error string with stderr surfaced (so an early HTTP-422 is detectable).
pub struct GhCliInvoker {
    program: String,
}

impl Default for GhCliInvoker {
    fn default() -> Self {
        Self {
            program: "gh".to_string(),
        }
    }
}

impl GhCliInvoker {
    /// Point at a non-default `gh` (absolute path / alternate name).
    pub fn with_program(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl GithubInvoker for GhCliInvoker {
    fn invoke(&self, token: &str, argv: &[String]) -> Result<Vec<u8>, String> {
        let out = std::process::Command::new(&self.program)
            .args(argv)
            // Token only ever reaches GitHub via the child env — never argv/logs.
            .env("GH_TOKEN", token)
            .output()
            .map_err(|e| format!("failed to spawn {}: {e}", self.program))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Err(format!(
                "{} api exited {}: {} {}",
                self.program,
                out.status,
                stderr.trim(),
                stdout.trim()
            ));
        }
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(c: Conclusion) -> Verdict {
        Verdict {
            head_sha: "deadbeef".into(),
            check_name: "flexnetos/merge-gate".into(),
            conclusion: c,
            summary: String::new(),
        }
    }

    #[test]
    fn only_green_is_armable() {
        assert!(ensure_armable(&verdict(Conclusion::Success)).is_ok());
        assert!(matches!(
            ensure_armable(&verdict(Conclusion::Failure)),
            Err(MergeGateError::NotGreen(_))
        ));
        assert!(matches!(
            ensure_armable(&verdict(Conclusion::ActionRequired)),
            Err(MergeGateError::NotGreen(_))
        ));
    }

    #[test]
    fn conclusion_strings_match_github() {
        assert_eq!(Conclusion::Success.as_str(), "success");
        assert_eq!(Conclusion::ActionRequired.as_str(), "action_required");
        assert!(Conclusion::Success.is_green());
        assert!(!Conclusion::Neutral.is_green());
    }

    #[test]
    fn unwired_gate_fails_closed() {
        let g = UnwiredMergeGate;
        assert!(matches!(
            g.post_verdict(&verdict(Conclusion::Success)),
            Err(MergeGateError::NotWired(_))
        ));
        assert!(matches!(
            g.arm_auto_merge(7),
            Err(MergeGateError::NotWired(_))
        ));
    }

    /// Records the (token, argv) the gate handed the invoker so tests can assert the token never
    /// leaked into argv. Returns canned responses as a **sequence** — one per `invoke` call — so a
    /// two-step flow (resolve node id → mutate) can be exercised end-to-end. A single-element
    /// sequence behaves like a constant invoker for the one-shot paths.
    struct FakeInvoker {
        results: std::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, String>>>,
        seen_token: std::sync::Mutex<Option<String>>,
        seen_argv: std::sync::Mutex<Option<Vec<String>>>,
        all_argv: std::sync::Mutex<Vec<Vec<String>>>,
    }
    impl FakeInvoker {
        fn new(result: Result<Vec<u8>, String>) -> Self {
            Self::sequence(vec![result])
        }
        fn sequence(results: Vec<Result<Vec<u8>, String>>) -> Self {
            Self {
                results: std::sync::Mutex::new(results.into_iter().collect()),
                seen_token: std::sync::Mutex::new(None),
                seen_argv: std::sync::Mutex::new(None),
                all_argv: std::sync::Mutex::new(Vec::new()),
            }
        }
    }
    impl GithubInvoker for FakeInvoker {
        fn invoke(&self, token: &str, argv: &[String]) -> Result<Vec<u8>, String> {
            *self.seen_token.lock().unwrap() = Some(token.to_string());
            *self.seen_argv.lock().unwrap() = Some(argv.to_vec());
            self.all_argv.lock().unwrap().push(argv.to_vec());
            // Pop the next canned response; reuse the last one if the sequence is exhausted.
            let mut q = self.results.lock().unwrap();
            if q.len() > 1 {
                q.pop_front().unwrap()
            } else {
                q.front().cloned().unwrap()
            }
        }
    }

    fn gate(result: Result<Vec<u8>, String>) -> GithubMergeGate<FakeInvoker> {
        GithubMergeGate::new(
            FakeInvoker::new(result),
            "FlexNetOS",
            "flexnetos_github_app",
            ScopedToken::new("ghs_supersecret", 1_700_000_000),
        )
    }

    fn gate_seq(results: Vec<Result<Vec<u8>, String>>) -> GithubMergeGate<FakeInvoker> {
        GithubMergeGate::new(
            FakeInvoker::sequence(results),
            "FlexNetOS",
            "flexnetos_github_app",
            ScopedToken::new("ghs_supersecret", 1_700_000_000),
        )
    }

    /// A canned step-1 response carrying a PR node id.
    fn resolve_ok(node_id: &str) -> Result<Vec<u8>, String> {
        Ok(
            format!(r#"{{"data":{{"repository":{{"pullRequest":{{"id":"{node_id}"}}}}}}}}"#)
                .into_bytes(),
        )
    }

    #[test]
    fn post_verdict_happy_path() {
        let g = gate(Ok(br#"{"id":123}"#.to_vec()));
        assert!(g.post_verdict(&verdict(Conclusion::Success)).is_ok());
        // Token was handed to the invoker (for GH_TOKEN) but never appeared in argv.
        assert_eq!(
            g.invoker.seen_token.lock().unwrap().as_deref(),
            Some("ghs_supersecret")
        );
        let argv = g.invoker.seen_argv.lock().unwrap().clone().unwrap();
        assert!(
            !argv.iter().any(|a| a.contains("ghs_supersecret")),
            "token leaked into argv: {argv:?}"
        );
    }

    #[test]
    fn post_verdict_transport_error_is_api() {
        let g = gate(Err("gh: connection refused".into()));
        assert!(matches!(
            g.post_verdict(&verdict(Conclusion::Success)),
            Err(MergeGateError::Api(_))
        ));
    }

    #[test]
    fn arm_auto_merge_two_step_success() {
        // Step 1 resolves the node id; step 2 enables auto-merge.
        let g = gate_seq(vec![
            resolve_ok("PR_kwDOauto123"),
            Ok(br#"{"data":{"enablePullRequestAutoMerge":{"pullRequest":{"autoMergeRequest":{"enabledAt":"2026-06-13T00:00:00Z"}}}}}"#.to_vec()),
        ]);
        assert!(g.arm_auto_merge(42).is_ok());
        // Exactly two calls were made: resolve then enable.
        let calls = g.invoker.all_argv.lock().unwrap().clone();
        assert_eq!(calls.len(), 2, "expected resolve+enable, got {calls:?}");
        // Step 1 was the resolve query (number → id), step 2 carried the resolved node id.
        assert!(calls[0].join(" ").contains("pullRequest(number:$pr){id}"));
        assert!(calls[1].join(" ").contains("enablePullRequestAutoMerge"));
        assert!(calls[1].iter().any(|a| a == "id=PR_kwDOauto123"));
        // Token never reached argv in either step.
        for argv in &calls {
            assert!(
                !argv.iter().any(|a| a.contains("ghs_supersecret")),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn arm_auto_merge_resolve_no_id_is_api() {
        // Step 1 succeeds transport-wise but carries no node id → fail closed as Api.
        let g = gate(Ok(
            br#"{"data":{"repository":{"pullRequest":null}}}"#.to_vec()
        ));
        assert!(matches!(g.arm_auto_merge(42), Err(MergeGateError::Api(_))));
        // Only the resolve step ran; the mutation was never attempted.
        assert_eq!(g.invoker.all_argv.lock().unwrap().len(), 1);
    }

    #[test]
    fn arm_auto_merge_resolve_422_is_requirements_not_met() {
        let g = gate(Err(
            "gh api exited exit status: 1: HTTP 422: requirements not yet satisfied".into(),
        ));
        assert!(matches!(
            g.arm_auto_merge(42),
            Err(MergeGateError::RequirementsNotMet)
        ));
    }

    #[test]
    fn arm_auto_merge_mutate_422_is_requirements_not_met() {
        // Step 1 resolves fine; the 422 surfaces in the mutate step.
        let g = gate_seq(vec![
            resolve_ok("PR_kwDOauto123"),
            Err("gh api exited exit status: 1: HTTP 422: requirements not yet satisfied".into()),
        ]);
        assert!(matches!(
            g.arm_auto_merge(42),
            Err(MergeGateError::RequirementsNotMet)
        ));
        // Both steps ran (resolve succeeded, mutate failed).
        assert_eq!(g.invoker.all_argv.lock().unwrap().len(), 2);
    }

    #[test]
    fn arm_auto_merge_other_error_is_api() {
        let g = gate(Err("gh: 500 internal server error".into()));
        assert!(matches!(g.arm_auto_merge(42), Err(MergeGateError::Api(_))));
    }

    #[test]
    fn check_run_argv_pins_the_github_contract() {
        let mut v = verdict(Conclusion::Success);
        v.summary = "all gates green".into();
        let argv = build_check_run_argv("FlexNetOS", "flexnetos_github_app", &v);
        let joined = argv.join(" ");
        assert_eq!(argv[0], "api");
        assert!(joined.contains("--method POST"), "{joined}");
        assert!(
            joined.contains("/repos/FlexNetOS/flexnetos_github_app/check-runs"),
            "{joined}"
        );
        assert!(joined.contains("conclusion=success"), "{joined}");
        assert!(joined.contains("head_sha=deadbeef"), "{joined}");
        assert!(joined.contains("name=flexnetos/merge-gate"), "{joined}");
        assert!(joined.contains("status=completed"), "{joined}");
        assert!(
            joined.contains("output[summary]=all gates green"),
            "{joined}"
        );
        // Never an APPROVE; never a token.
        assert!(!joined.contains("APPROVE"), "{joined}");
        assert!(!joined.to_lowercase().contains("ghs_"), "{joined}");
    }

    #[test]
    fn resolve_pr_node_id_argv_pins_the_graphql_contract() {
        let argv = build_resolve_pr_node_id_argv("FlexNetOS", "flexnetos_github_app", 42);
        let joined = argv.join(" ");
        assert_eq!(argv[0], "api");
        assert_eq!(argv[1], "graphql");
        // The query resolves the PR node id from its number.
        assert!(
            joined.contains("repository(owner:$owner,name:$repo)"),
            "{joined}"
        );
        assert!(joined.contains("pullRequest(number:$pr){id}"), "{joined}");
        assert!(joined.contains("owner=FlexNetOS"), "{joined}");
        assert!(joined.contains("repo=flexnetos_github_app"), "{joined}");
        // The PR number is passed typed as an Int via `-F pr=`.
        let pr_idx = argv.iter().position(|a| a == "pr=42").expect("pr=42 arg");
        assert_eq!(argv[pr_idx - 1], "-F", "pr must be typed via -F: {joined}");
        // No mutation in the resolve step; never an APPROVE; never a token.
        assert!(!joined.contains("enablePullRequestAutoMerge"), "{joined}");
        assert!(!joined.contains("APPROVE"), "{joined}");
        assert!(!joined.to_lowercase().contains("ghs_"), "{joined}");
    }

    #[test]
    fn enable_auto_merge_argv_pins_the_graphql_contract() {
        let argv = build_enable_auto_merge_argv("PR_kwDOauto123");
        let joined = argv.join(" ");
        assert_eq!(argv[0], "api");
        assert_eq!(argv[1], "graphql");
        assert!(joined.contains("enablePullRequestAutoMerge"), "{joined}");
        assert!(joined.contains("SQUASH"), "{joined}");
        // The resolved node id is passed typed via `-F id=`.
        let id_idx = argv
            .iter()
            .position(|a| a == "id=PR_kwDOauto123")
            .expect("id=… arg");
        assert_eq!(argv[id_idx - 1], "-F", "id must be passed via -F: {joined}");
        // Never an APPROVE; never a token.
        assert!(!joined.contains("APPROVE"), "{joined}");
        assert!(!joined.to_lowercase().contains("ghs_"), "{joined}");
    }
}
