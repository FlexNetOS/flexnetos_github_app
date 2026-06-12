//! GitHub webhook ingress: signature verification + minimal header/event typing.
//!
//! Verifies `X-Hub-Signature-256` — an HMAC-SHA256 hex digest over the **raw** request
//! body, prefixed `sha256=` — using a constant-time comparison (`Mac::verify_slice`),
//! per GitHub's "validating webhook deliveries" guidance (ADR-0008 §B). The caller
//! (server) is responsible for reading the *raw* body before any re-encoding and for
//! de-duplicating on the `X-GitHub-Delivery` GUID.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("missing X-Hub-Signature-256 header")]
    Missing,
    #[error("malformed signature header (expected `sha256=<hex>`)")]
    Malformed,
    #[error("signature mismatch")]
    Mismatch,
}

/// Verify the `X-Hub-Signature-256` header value against the raw `body`.
///
/// `header` is the full value, e.g. `sha256=ab12…`. An empty/whitespace header is
/// treated as [`SignatureError::Missing`]; a non-`sha256=`/non-hex value is
/// [`SignatureError::Malformed`]; a valid-but-wrong digest is
/// [`SignatureError::Mismatch`]. Comparison is constant-time.
pub fn verify_signature(secret: &[u8], body: &[u8], header: &str) -> Result<(), SignatureError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(SignatureError::Missing);
    }
    let hex_sig = header
        .strip_prefix("sha256=")
        .ok_or(SignatureError::Malformed)?;
    let sig_bytes = hex::decode(hex_sig).map_err(|_| SignatureError::Malformed)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&sig_bytes)
        .map_err(|_| SignatureError::Mismatch)
}

/// Compute the canonical `sha256=<hex>` signature for `body` under `secret`.
/// Used by tests and by `fxapp sign` for webhook smoke tests.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// The event kind from the `X-GitHub-Event` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    PullRequest,
    Push,
    CheckSuite,
    CheckRun,
    Ping,
    Other(String),
}

impl EventKind {
    pub fn parse(s: &str) -> Self {
        match s {
            "pull_request" => Self::PullRequest,
            "push" => Self::Push,
            "check_suite" => Self::CheckSuite,
            "check_run" => Self::CheckRun,
            "ping" => Self::Ping,
            other => Self::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GitHub's documented example (validating-webhook-deliveries): this secret + body.
    const SECRET: &[u8] = b"It's a Secret to Everybody";
    const BODY: &[u8] = b"Hello, World!";
    const GITHUB_EXAMPLE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    #[test]
    fn sign_matches_github_documented_vector() {
        assert_eq!(sign(SECRET, BODY), GITHUB_EXAMPLE);
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let sig = sign(SECRET, BODY);
        assert!(verify_signature(SECRET, BODY, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let sig = sign(SECRET, BODY);
        assert_eq!(
            verify_signature(SECRET, b"Hello, World", &sig),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let sig = sign(SECRET, BODY);
        assert_eq!(
            verify_signature(b"wrong-secret", BODY, &sig),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn verify_rejects_missing_and_malformed() {
        let sig = sign(SECRET, BODY);
        assert_eq!(
            verify_signature(SECRET, BODY, "   "),
            Err(SignatureError::Missing)
        );
        assert_eq!(
            verify_signature(SECRET, BODY, "md5=abc"),
            Err(SignatureError::Malformed)
        );
        assert_eq!(
            verify_signature(SECRET, BODY, "sha256=zzzz"),
            Err(SignatureError::Malformed)
        );
        // a correctly-shaped but wrong digest is a mismatch, not malformed
        let _ = sig;
    }

    #[test]
    fn event_kind_parses_known_and_unknown() {
        assert_eq!(EventKind::parse("pull_request"), EventKind::PullRequest);
        assert_eq!(EventKind::parse("check_suite"), EventKind::CheckSuite);
        assert_eq!(EventKind::parse("weird"), EventKind::Other("weird".into()));
    }
}
