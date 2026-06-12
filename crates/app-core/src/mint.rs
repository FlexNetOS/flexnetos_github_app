//! Installation-token minting seam → **envctl** `ProviderMint` (ADR-0008 S1, ADR-0007).
//!
//! The App private key lives in envctl's vault; envctl exchanges the App-JWT for a
//! short-lived (≤1h GitHub, clamped ≤24h by envctl), per-repository, per-permission
//! installation token. This module defines the request/response contract and the
//! [`TokenMinter`] trait the server depends on. [`EnvctlMinter`] (P1) delegates to envctl via
//! the [`MintInvoker`] seam — the production [`SecretctlInvoker`] shells `secretctl mint-github`,
//! which talks to `secretd` over UDS and mints from the vault-sealed key. [`UnwiredMinter`]
//! remains the explicit fail-closed default until a minter is configured.

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

/// The seam to envctl's minting surface. The production [`SecretctlInvoker`] shells
/// `secretctl mint-github`; tests inject a fake so the request/parse contract is proven without a
/// live `secretd`. Returns raw stdout (`{"token","expires_at_unix"}` on success) or a transport
/// error string (non-zero exit / spawn failure).
pub trait MintInvoker: Send + Sync {
    fn invoke(&self, req: &InstallationTokenRequest) -> Result<Vec<u8>, String>;
}

/// The wired [`TokenMinter`] (P1): delegates to envctl through a [`MintInvoker`]. The App private
/// key NEVER enters this process — envctl mints from the vault-sealed key (ADR-0008 S1). Generic
/// over the invoker so the daemon path is exercised with a fake (no live `secretd`) in tests.
pub struct EnvctlMinter<I: MintInvoker> {
    invoker: I,
}

impl<I: MintInvoker> EnvctlMinter<I> {
    pub fn new(invoker: I) -> Self {
        Self { invoker }
    }
}

impl<I: MintInvoker> TokenMinter for EnvctlMinter<I> {
    fn mint(&self, req: &InstallationTokenRequest) -> Result<ScopedToken, MintError> {
        let raw = self.invoker.invoke(req).map_err(MintError::Unavailable)?;
        parse_mint_output(&raw)
    }
}

/// Parse envctl's machine output (`{"token","expires_at_unix"}`) into a [`ScopedToken`]. A missing
/// token after a clean call is treated as a broker denial (fail-closed; never a plaintext PAT).
fn parse_mint_output(raw: &[u8]) -> Result<ScopedToken, MintError> {
    #[derive(serde::Deserialize)]
    struct Out {
        token: String,
        expires_at_unix: u64,
    }
    let out: Out = serde_json::from_slice(raw)
        .map_err(|e| MintError::Unavailable(format!("malformed mint output: {e}")))?;
    if out.token.is_empty() {
        return Err(MintError::Denied("envctl returned an empty token".into()));
    }
    Ok(ScopedToken::new(out.token, out.expires_at_unix))
}

/// The argv `EnvctlMinter` runs against envctl. Pure (unit-tested) so the wire contract is pinned
/// independently of process execution:
/// `secretctl mint-github --installation-id N --ttl-secs T --output json
/// [--repository-ids a,b] [--permissions name:access,...]`.
pub fn build_argv(program: &str, req: &InstallationTokenRequest) -> Vec<String> {
    let mut argv = vec![
        program.to_string(),
        "mint-github".to_string(),
        "--installation-id".to_string(),
        req.installation_id.to_string(),
        "--ttl-secs".to_string(),
        req.ttl.as_secs().to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    if !req.repository_ids.is_empty() {
        argv.push("--repository-ids".to_string());
        argv.push(
            req.repository_ids
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !req.permissions.is_empty() {
        argv.push("--permissions".to_string());
        argv.push(
            req.permissions
                .iter()
                .map(|p| {
                    let access = match p.access {
                        Access::Read => "read",
                        Access::Write => "write",
                    };
                    format!("{}:{}", p.name, access)
                })
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    argv
}

/// Production [`MintInvoker`]: shells `secretctl mint-github --output json`. `secretctl` talks to
/// `secretd` over UDS and mints from the vault-sealed App key, so the App private key never enters
/// this process. A non-zero exit (incl. broker denial) becomes the error string (stderr surfaced).
pub struct SecretctlInvoker {
    program: String,
}

impl Default for SecretctlInvoker {
    fn default() -> Self {
        Self {
            program: "secretctl".to_string(),
        }
    }
}

impl SecretctlInvoker {
    /// Point at a non-default `secretctl` (absolute path / alternate name).
    pub fn with_program(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl MintInvoker for SecretctlInvoker {
    fn invoke(&self, req: &InstallationTokenRequest) -> Result<Vec<u8>, String> {
        let argv = build_argv(&self.program, req);
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| format!("failed to spawn {}: {e}", self.program))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "{} mint-github exited {}: {}",
                self.program,
                out.status,
                stderr.trim()
            ));
        }
        Ok(out.stdout)
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

    struct FakeInvoker(Result<Vec<u8>, String>);
    impl MintInvoker for FakeInvoker {
        fn invoke(&self, _req: &InstallationTokenRequest) -> Result<Vec<u8>, String> {
            self.0.clone()
        }
    }

    fn sample_req() -> InstallationTokenRequest {
        InstallationTokenRequest {
            installation_id: 99,
            repository_ids: vec![10, 20],
            permissions: vec![
                Permission::checks_write(),
                Permission {
                    name: "contents".into(),
                    access: Access::Read,
                },
            ],
            ttl: Duration::from_secs(3600),
        }
    }

    #[test]
    fn envctl_minter_parses_token() {
        let m = EnvctlMinter::new(FakeInvoker(Ok(
            br#"{"token":"ghs_abc","expires_at_unix":1700000000}"#.to_vec(),
        )));
        let tok = m.mint(&sample_req()).expect("mint ok");
        assert_eq!(tok.expose(), "ghs_abc");
        assert_eq!(tok.expires_at_unix, 1_700_000_000);
    }

    #[test]
    fn envctl_minter_transport_error_is_unavailable() {
        let m = EnvctlMinter::new(FakeInvoker(Err("secretd not running".into())));
        assert!(matches!(
            m.mint(&sample_req()),
            Err(MintError::Unavailable(_))
        ));
    }

    #[test]
    fn envctl_minter_empty_token_is_denied() {
        let m = EnvctlMinter::new(FakeInvoker(Ok(
            br#"{"token":"","expires_at_unix":1}"#.to_vec()
        )));
        assert!(matches!(m.mint(&sample_req()), Err(MintError::Denied(_))));
    }

    #[test]
    fn envctl_minter_malformed_output_is_unavailable() {
        let m = EnvctlMinter::new(FakeInvoker(Ok(br#"{"nope":true}"#.to_vec())));
        assert!(matches!(
            m.mint(&sample_req()),
            Err(MintError::Unavailable(_))
        ));
    }

    #[test]
    fn argv_pins_the_envctl_contract() {
        let argv = build_argv("secretctl", &sample_req());
        let joined = argv.join(" ");
        assert_eq!(argv[0], "secretctl");
        assert_eq!(argv[1], "mint-github");
        assert!(joined.contains("--installation-id 99"), "{joined}");
        assert!(joined.contains("--ttl-secs 3600"), "{joined}");
        assert!(joined.contains("--output json"), "{joined}");
        assert!(joined.contains("--repository-ids 10,20"), "{joined}");
        assert!(
            joined.contains("--permissions checks:write,contents:read"),
            "{joined}"
        );
    }
}
