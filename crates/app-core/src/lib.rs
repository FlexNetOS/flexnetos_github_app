//! `app-core` — the pure, non-printing core of `flexnetos_github_app` (ADR-0008 §1).
//!
//! Responsibilities, each in its own module as a typed seam the front-ends drive:
//! - [`webhook`] — GitHub webhook ingress: constant-time `X-Hub-Signature-256` verification.
//! - [`jwt`] — GitHub App JWT (RS256) claim construction + signing (key from envctl, P1).
//! - [`mint`] — installation-token minting seam → envctl `ProviderMint` (P1).
//! - [`merge_gate`] — verdict-as-check-run executor + auto-merge guard (P3).
//! - [`router`] — verified-event → local dispatch + protected-files denylist.
//!
//! This layer performs no network/disk I/O itself; concrete impls (secretd UDS client,
//! GitHub REST) live behind the traits here and are wired in `app-server`.

pub mod error;
pub mod jwt;
pub mod merge_gate;
pub mod mint;
pub mod router;
pub mod webhook;

pub use error::{CoreError, Result};
