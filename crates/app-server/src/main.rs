//! `fxapp-server` — webhook ingress for `flexnetos_github_app` (ADR-0008 §1).
//!
//! P0/P2 surface: `GET /health` and `POST /webhook`. The webhook handler reads the **raw**
//! body, verifies `X-Hub-Signature-256` (constant-time) via `app_core::webhook`, then (P2)
//! parses the payload, routes it (`app_core::router`), and dispatches a **signed JobSpec**
//! envelope to `flexnetos_runner` over its Unix-domain socket. envctl token minting (P1) and
//! the merge-gate (P3) build on `app-core`'s typed seams. Binds to localhost by design —
//! expose via a tunnel (cloudflared/smee), never a public listener (ADR-0008 §4).

use std::net::SocketAddr;
use std::sync::Arc;

use app_core::router::{self, Dispatch};
use app_core::webhook::{verify_signature, EventKind};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};

#[derive(Clone)]
struct AppState {
    /// Webhook HMAC secret. In P1 this is fetched from envctl's vault, not the env.
    webhook_secret: Arc<Vec<u8>>,
    /// Dispatch config: the runner's UDS path and the JobSpec signing key (P3: envctl vault).
    /// `None` socket ⇒ accept-and-log without dispatching (the front door still works).
    dispatch: Arc<DispatchConfig>,
}

struct DispatchConfig {
    socket: Option<std::path::PathBuf>,
    key: Vec<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fxapp_server=info,app_core=info".into()),
        )
        .init();

    // P1: source from envctl secretd, not the environment. Empty ⇒ fail closed.
    let secret = std::env::var("FXAPP_WEBHOOK_SECRET")
        .map(String::into_bytes)
        .unwrap_or_default();
    // P3: dispatch socket + signing key come from envctl. Absent socket ⇒ no dispatch.
    let dispatch = DispatchConfig {
        socket: std::env::var_os("FXAPP_DISPATCH_SOCKET").map(std::path::PathBuf::from),
        key: std::env::var("FXAPP_DISPATCH_KEY")
            .map(String::into_bytes)
            .unwrap_or_default(),
    };
    let state = AppState {
        webhook_secret: Arc::new(secret),
        dispatch: Arc::new(dispatch),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/webhook", post(webhook))
        .with_state(state);

    let addr: SocketAddr = std::env::var("FXAPP_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()?;
    tracing::info!(%addr, "fxapp-server listening (local; expose via tunnel)");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn webhook(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if st.webhook_secret.is_empty() {
        tracing::error!("no webhook secret configured (P1: envctl vault); refusing");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let signature = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Err(e) = verify_signature(&st.webhook_secret, &body, signature) {
        tracing::warn!(error = %e, "rejected webhook (signature)");
        return StatusCode::UNAUTHORIZED;
    }
    let event = headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let delivery = headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let kind = EventKind::parse(event);
    tracing::info!(event, delivery, kind = ?kind, "accepted webhook");

    // P2: parse the payload, route it, and dispatch a signed JobSpec to the runner.
    // Dispatch is best-effort: a routing/transport failure is logged but we still ack 2xx,
    // because a non-2xx makes GitHub redeliver — durability is the ledger's job (P3), not retry.
    dispatch_event(&st, kind, delivery, &body);
    StatusCode::ACCEPTED
}

/// Parse → route → sign → send. Pure decisions live in `app_core::router`/`dispatch`; this
/// only wires them to the live socket. No-ops (logged) when there is nothing to dispatch or
/// no socket is configured.
fn dispatch_event(st: &AppState, kind: EventKind, delivery: String, body: &[u8]) {
    let payload: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "webhook body is not JSON; nothing to dispatch");
            return;
        }
    };
    let ctx = router::event_context_from_payload(kind, &payload);
    let routed = router::route(&ctx);
    if matches!(routed, Dispatch::Ignore) {
        tracing::debug!("event routes to Ignore; no dispatch");
        return;
    }
    let from_fork = router::payload_is_from_fork(&payload);
    let meta = app_core::dispatch::JobMeta {
        // The delivery GUID is unique per webhook delivery — reuse it as the runner's dedup key.
        id: delivery.clone(),
        correlation_id: delivery,
        from_fork,
    };
    let Some(frame) = app_core::dispatch::build_frame(&st.dispatch.key, &meta, &routed) else {
        return;
    };
    send_frame(st.dispatch.clone(), frame);
}

/// Send a signed frame to the runner over UDS, off the async runtime (blocking std socket).
#[cfg(unix)]
fn send_frame(dispatch: Arc<DispatchConfig>, frame: app_core::dispatch::DispatchRequest) {
    let Some(socket) = dispatch.socket.clone() else {
        tracing::warn!("FXAPP_DISPATCH_SOCKET unset; built a signed frame but did not dispatch");
        return;
    };
    tokio::task::spawn_blocking(move || match app_core::dispatch::send(&socket, &frame) {
        Ok(resp) if resp.accepted => {
            tracing::info!(kernel = ?resp.kernel, placement = ?resp.placement, "runner accepted dispatch")
        }
        Ok(resp) => tracing::warn!(error = ?resp.error, "runner rejected dispatch"),
        Err(e) => tracing::error!(error = %e, "dispatch transport failed"),
    });
}

#[cfg(not(unix))]
fn send_frame(_dispatch: Arc<DispatchConfig>, _frame: app_core::dispatch::DispatchRequest) {
    tracing::warn!("UDS dispatch is unix-only; skipping on this platform");
}
