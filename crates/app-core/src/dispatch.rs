//! P2 dispatch (ADR-0008 §S7): routed event → signed JobSpec envelope → `flexnetos_runner`.
//!
//! The app decides *what* to dispatch ([`crate::router`]); this module turns that decision
//! into the signed frame the runner accepts over its Unix-domain dispatch socket.
//!
//! **"Sign what you send".** We build the JobSpec JSON once, HMAC-SHA256 the *exact* bytes,
//! and transmit a 2-field envelope `{spec_json, signature}`. The runner verifies those bytes
//! (constant-time) *before* parsing, so the app mirrors only this envelope — never the runner's
//! `JobSpec` type. A new optional field on the runner's `JobSpec` can never desync the contract:
//! both sides agree on bytes, not on a shared struct. (Same property as webhook body verification
//! in [`crate::webhook`].)
//!
//! The signing key is sealed in envctl's vault and injected at the boundary (P3); this module
//! takes it as a slice and never logs or stores it.

use crate::router::Dispatch;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Identity + provenance the runner needs around the job payload.
///
/// `from_fork` is load-bearing: it drives the runner's fork-PR isolation (a fork-triggered
/// job is refused at the dispatch boundary and never reaches self-hosted hardware — ADR-0008 §6).
/// The server sets it from the webhook payload (`pull_request.head.repo.fork` / head-repo ≠ base-repo).
#[derive(Debug, Clone)]
pub struct JobMeta {
    /// Unique job id — the runner's dedup key.
    pub id: String,
    /// Ties the job back to the originating webhook delivery (`X-GitHub-Delivery`).
    pub correlation_id: String,
    /// Whether the triggering event came from a fork.
    pub from_fork: bool,
}

/// The wire envelope sent to the runner — mirror of `runner-core::wire::DispatchRequest`.
/// `signature` is `sha256=<hex>` HMAC-SHA256 over the exact `spec_json` bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchRequest {
    pub spec_json: String,
    pub signature: String,
}

/// The runner's reply — mirror of `runner-core::wire::DispatchResponse`. Fields are present
/// only on an accepted dispatch (`error` only on rejection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DispatchResponse {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Map a routed [`Dispatch`] to the runner's `JobKind` JSON (tagged `kind`, snake_case).
/// `None` for [`Dispatch::Ignore`] — nothing to send.
fn job_json(d: &Dispatch) -> Option<serde_json::Value> {
    match d {
        Dispatch::Ci { repo, head_sha } => Some(json!({
            "kind": "ci",
            "repo": repo,
            "head_sha": head_sha,
        })),
        Dispatch::ReviewGate {
            repo,
            pr_number,
            head_sha,
        } => Some(json!({
            "kind": "review_gate",
            "repo": repo,
            "pr_number": pr_number,
            "head_sha": head_sha,
        })),
        Dispatch::Ignore => None,
    }
}

/// Build the signed dispatch envelope for a routed event. `None` when there is nothing to
/// dispatch ([`Dispatch::Ignore`]).
pub fn build_frame(key: &[u8], meta: &JobMeta, d: &Dispatch) -> Option<DispatchRequest> {
    let job = job_json(d)?;
    let spec = json!({
        "id": meta.id,
        "correlation_id": meta.correlation_id,
        "from_fork": meta.from_fork,
        "job": job,
    });
    // Sign exactly the bytes we transmit (see module docs).
    let spec_json = serde_json::to_string(&spec).expect("JobSpec value serializes");
    let signature = sign_bytes(key, spec_json.as_bytes());
    Some(DispatchRequest {
        spec_json,
        signature,
    })
}

/// `sha256=<hex>` HMAC-SHA256 of `msg` under `key`.
fn sign_bytes(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Send a signed frame to the runner's dispatch socket and read its response.
///
/// Unix-only: the runner listens on a Unix-domain socket (`fxrun-dispatch --socket`). The
/// client writes the envelope, half-closes the write side so the server's `read_to_end`
/// completes, then reads the JSON reply.
#[cfg(unix)]
pub fn send(
    socket_path: &std::path::Path,
    req: &DispatchRequest,
) -> std::io::Result<DispatchResponse> {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let bytes = serde_json::to_vec(req)?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A faithful mirror of `runner-core::jobspec::{JobSpec, JobKind}` — pins the cross-repo
    // contract from the app side: whatever `build_frame` emits MUST parse into this with the
    // expected values (this is exactly what the runner does after verifying the bytes).
    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "kind")]
    enum MirrorJobKind {
        Ci {
            repo: String,
            head_sha: String,
        },
        ReviewGate {
            repo: String,
            pr_number: u64,
            head_sha: String,
        },
        #[allow(dead_code)]
        AgentTask {
            repo: String,
            prompt_ref: String,
        },
        #[allow(dead_code)]
        LoopCycle {
            repo: String,
            task_id: String,
        },
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    struct MirrorJobSpec {
        id: String,
        correlation_id: String,
        from_fork: bool,
        job: MirrorJobKind,
    }

    fn meta() -> JobMeta {
        JobMeta {
            id: "job-1".into(),
            correlation_id: "delivery-9".into(),
            from_fork: false,
        }
    }

    #[test]
    fn ignore_produces_no_frame() {
        assert!(build_frame(b"k", &meta(), &Dispatch::Ignore).is_none());
    }

    #[test]
    fn frame_signs_exactly_the_bytes_it_sends() {
        let d = Dispatch::Ci {
            repo: "FlexNetOS/x".into(),
            head_sha: "abc".into(),
        };
        let frame = build_frame(b"k", &meta(), &d).expect("ci dispatches");
        // Recompute the HMAC over the transmitted spec_json — must equal the signature.
        assert_eq!(
            frame.signature,
            sign_bytes(b"k", frame.spec_json.as_bytes())
        );
    }

    #[test]
    fn ci_frame_parses_as_runner_jobspec() {
        let d = Dispatch::Ci {
            repo: "FlexNetOS/x".into(),
            head_sha: "abc".into(),
        };
        let frame = build_frame(b"k", &meta(), &d).unwrap();
        let spec: MirrorJobSpec = serde_json::from_str(&frame.spec_json).expect("runner parses it");
        assert_eq!(
            spec,
            MirrorJobSpec {
                id: "job-1".into(),
                correlation_id: "delivery-9".into(),
                from_fork: false,
                job: MirrorJobKind::Ci {
                    repo: "FlexNetOS/x".into(),
                    head_sha: "abc".into(),
                },
            }
        );
    }

    #[test]
    fn review_gate_frame_parses_as_runner_jobspec() {
        let d = Dispatch::ReviewGate {
            repo: "FlexNetOS/x".into(),
            pr_number: 7,
            head_sha: "deadbeef".into(),
        };
        let m = JobMeta {
            id: "job-2".into(),
            correlation_id: "delivery-10".into(),
            from_fork: true,
        };
        let frame = build_frame(b"k", &m, &d).unwrap();
        let spec: MirrorJobSpec = serde_json::from_str(&frame.spec_json).unwrap();
        assert_eq!(
            spec,
            MirrorJobSpec {
                id: "job-2".into(),
                correlation_id: "delivery-10".into(),
                from_fork: true,
                job: MirrorJobKind::ReviewGate {
                    repo: "FlexNetOS/x".into(),
                    pr_number: 7,
                    head_sha: "deadbeef".into(),
                },
            }
        );
    }

    // Round-trip the exact frame through a throwaway Unix socket whose listener replays the
    // runner's accept path: verify the signature over the received bytes, parse, then reply.
    // Proves the app's bytes/signature are precisely what a runner accepts.
    #[cfg(unix)]
    #[test]
    fn uds_roundtrip_runner_accepts_app_frame() {
        use std::io::{Read, Write};
        use std::net::Shutdown;
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fxapp-dispatch-test-{}-{}.sock",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind");
        let key: &[u8] = b"shared-secret";

        // Listener replays the runner's accept path on a single connection: verify the
        // signature over the *received* bytes, parse, then reply.
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut raw = Vec::new();
            conn.read_to_end(&mut raw).expect("read frame");
            let req: DispatchRequest = serde_json::from_slice(&raw).expect("envelope parses");
            let verified = sign_bytes(key, req.spec_json.as_bytes()) == req.signature;
            let parsed: Option<MirrorJobSpec> = serde_json::from_str(&req.spec_json).ok();
            let resp = DispatchResponse {
                accepted: verified && parsed.is_some(),
                kernel: Some("loop".into()),
                placement: Some("SelfHosted".into()),
                intent: Some("ci".into()),
                error: None,
            };
            conn.write_all(&serde_json::to_vec(&resp).unwrap()).unwrap();
            conn.flush().unwrap();
            let _ = conn.shutdown(Shutdown::Write);
        });

        let frame = build_frame(
            key,
            &JobMeta {
                id: "job-uds".into(),
                correlation_id: "delivery-uds".into(),
                from_fork: false,
            },
            &Dispatch::Ci {
                repo: "FlexNetOS/x".into(),
                head_sha: "abc".into(),
            },
        )
        .unwrap();

        let resp = send(&path, &frame).expect("send succeeds");
        server.join().expect("server thread");
        let _ = std::fs::remove_file(&path);

        assert!(resp.accepted, "runner accepts the app's signed frame");
        assert_eq!(resp.kernel.as_deref(), Some("loop"));
    }
}
