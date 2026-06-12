//! Merge-gate executor (ADR-0008 §1/S4). Posts the gatekeeper verdict as a GitHub
//! **check-run** (wired as a *required status check*) and arms native auto-merge — but
//! only **after** the verdict is green, structurally avoiding the ~2026-03 HTTP-422
//! "requirements not yet satisfied" behavior (ADR-0008 §B). It is **never** a native
//! `github-actions[bot]` APPROVE (bypasses branch protection, #25439). The concrete
//! GitHub-REST impl lands in P3; [`UnwiredMergeGate`] fails closed until then.

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

/// P0 placeholder: fails closed until the GitHub check-runs/auto-merge REST client
/// lands (P3).
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
}
