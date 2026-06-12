//! Installation-token minting seam → **envctl** `ProviderMint` (ADR-0008 S1, ADR-0007).
//!
//! The App private key lives in envctl's vault; envctl exchanges the App-JWT for a
//! short-lived (≤1h GitHub, clamped ≤24h by envctl), per-repository, per-permission
//! installation token. This module defines the request/response contract and the
//! [`TokenMinter`] trait the server depends on. The concrete `EnvctlMinter` (secretd
//! over UDS) is wired in P1; until then [`UnwiredMinter`] fails closed.

use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// A least-privilege permission requested for a token (GitHub permission name + access).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub name: String,
    pub access: Access,
}

impl Permission {
    pub fn checks_write() -> Self {
        Self {
            name: "checks".into(),
            access: Access::Write,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallationTokenRequest {
    pub installation_id: u64,
    /// Restrict the token to specific repos (GitHub allows ≤500). Empty ⇒ installation default.
    pub repository_ids: Vec<u64>,
    pub permissions: Vec<Permission>,
    /// Requested lifetime; GitHub caps installation tokens at 1h and envctl clamps ≤24h.
    pub ttl: Duration,
}

/// A minted, short-lived scoped token. `Debug` is redacted so it can't leak via logs.
pub struct ScopedToken {
    token: String,
    pub expires_at_unix: u64,
}

impl ScopedToken {
    pub fn new(token: impl Into<String>, expires_at_unix: u64) -> Self {
        Self {
            token: token.into(),
            expires_at_unix,
        }
    }
    /// Borrow the secret value. Callers MUST NOT log it.
    pub fn expose(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for ScopedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedToken")
            .field("token", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum MintError {
    #[error("envctl secretd unavailable: {0}")]
    Unavailable(String),
    #[error("mint denied by broker: {0}")]
    Denied(String),
    #[error("not yet wired ({0})")]
    NotWired(&'static str),
}

/// The minting seam the App depends on. The production impl calls envctl `secretd` over
/// UDS (`ProviderMint::mint_scoped`) and never holds the App private key in-process.
pub trait TokenMinter: Send + Sync {
    fn mint(&self, req: &InstallationTokenRequest) -> Result<ScopedToken, MintError>;
}

/// P0 placeholder: fails closed until the envctl secretd client lands (P1). Never
/// falls back to a plaintext PAT (ADR-0008 risk note).
#[derive(Default)]
pub struct UnwiredMinter;

impl TokenMinter for UnwiredMinter {
    fn mint(&self, _req: &InstallationTokenRequest) -> Result<ScopedToken, MintError> {
        Err(MintError::NotWired("EnvctlMinter secretd UDS — P1"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_debug_is_redacted_but_exposable() {
        let t = ScopedToken::new("ghs_supersecretvalue", 42);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("supersecret"));
        assert_eq!(t.expose(), "ghs_supersecretvalue");
        assert_eq!(t.expires_at_unix, 42);
    }

    #[test]
    fn unwired_minter_fails_closed() {
        let req = InstallationTokenRequest {
            installation_id: 1,
            repository_ids: vec![10],
            permissions: vec![Permission::checks_write()],
            ttl: Duration::from_secs(3600),
        };
        assert!(matches!(
            UnwiredMinter.mint(&req),
            Err(MintError::NotWired(_))
        ));
    }
}
