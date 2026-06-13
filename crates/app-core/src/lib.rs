//! `app-core` — the pure, non-printing core of `flexnetos_github_app` (ADR-0008 §1).
//!
//! Responsibilities, each in its own module as a typed seam the front-ends drive:
//! - [`webhook`] — GitHub webhook ingress: constant-time `X-Hub-Signature-256` verification.
//! - [`jwt`] — GitHub App JWT (RS256) claim construction + signing (key from envctl, P1).
//! - [`mint`] — installation-token minting seam → envctl `ProviderMint` (P1).
//! - [`merge_gate`] — verdict-as-check-run executor + auto-merge guard (P3).
//! - [`router`] — verified-event → local dispatch + protected-files denylist.
//! - [`dispatch`] — routed dispatch → signed JobSpec envelope → `flexnetos_runner` over UDS (P2).
//!
//! This layer performs no network/disk I/O itself; concrete impls (secretd UDS client,
//! GitHub REST) live behind the traits here and are wired in `app-server`. The one exception
//! is the unix-gated [`dispatch::send`] UDS client — the runner's dispatch socket is the app's
//! single outbound IPC, kept here so the envelope and its transport stay together.

pub mod dispatch;
pub mod error;
pub mod jwt;
pub mod merge_gate;
pub mod mint;
pub mod router;
pub mod webhook;

pub use dispatch::{build_frame, DispatchRequest, DispatchResponse, JobMeta};
pub use error::{CoreError, Result};
