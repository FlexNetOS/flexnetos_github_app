//! GitHub App JWT (RS256). Per GitHub's "generating a JWT" guidance:
//! `iss` = the App ID, `iat` = now − 60s (clock-drift allowance), `exp` ≤ now + 10 min.
//! The App private key is sealed in **envctl**'s vault (ADR-0008 S1); this layer only
//! builds the claims and signs them when handed a key — it never stores one.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// GitHub's hard cap on App-JWT lifetime.
pub const MAX_JWT_TTL: Duration = Duration::from_secs(600);
/// Clock-drift backdating applied to `iat`.
pub const CLOCK_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppClaims {
    /// App ID (or client ID).
    pub iss: String,
    /// Issued-at (unix seconds), backdated by [`CLOCK_SKEW`].
    pub iat: u64,
    /// Expiry (unix seconds), clamped so `exp − iat ≤ MAX_JWT_TTL + CLOCK_SKEW`.
    pub exp: u64,
}

impl AppClaims {
    /// Build claims for `app_id` at wall-clock `now`, requesting `ttl` (clamped to the
    /// 10-minute cap), with `iat` backdated by the clock-skew allowance.
    pub fn new(app_id: &str, now: SystemTime, ttl: Duration) -> Self {
        let now_s = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let iat = now_s.saturating_sub(CLOCK_SKEW.as_secs());
        let ttl = ttl.min(MAX_JWT_TTL);
        let exp = now_s + ttl.as_secs();
        Self {
            iss: app_id.to_string(),
            iat,
            exp,
        }
    }
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("invalid RSA private key: {0}")]
    Key(String),
    #[error("jwt encode failed: {0}")]
    Encode(String),
}

/// Sign App `claims` into a compact RS256 JWT using a PEM-encoded RSA private key.
/// In production the PEM is fetched from envctl's vault and zeroized by the caller.
pub fn sign_rs256(claims: &AppClaims, rsa_pem: &[u8]) -> Result<String, JwtError> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let key = EncodingKey::from_rsa_pem(rsa_pem).map_err(|e| JwtError::Key(e.to_string()))?;
    encode(&Header::new(Algorithm::RS256), claims, &key)
        .map_err(|e| JwtError::Encode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_backdate_iat_and_clamp_exp() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let c = AppClaims::new("12345", now, Duration::from_secs(3600)); // request 1h
        assert_eq!(c.iss, "12345");
        assert_eq!(c.iat, 1_000_000 - 60); // backdated by skew
        assert_eq!(c.exp, 1_000_000 + 600); // clamped to 10 min
    }

    #[test]
    fn ttl_under_cap_is_preserved() {
        let now = UNIX_EPOCH + Duration::from_secs(2_000);
        let c = AppClaims::new("1", now, Duration::from_secs(120));
        assert_eq!(c.exp, 2_000 + 120);
    }

    #[test]
    fn bad_key_is_rejected() {
        let c = AppClaims::new(
            "1",
            UNIX_EPOCH + Duration::from_secs(10),
            Duration::from_secs(60),
        );
        assert!(matches!(
            sign_rs256(&c, b"not a pem"),
            Err(JwtError::Key(_))
        ));
    }
}
