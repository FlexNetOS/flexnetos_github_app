//! `fxapp-server` — webhook ingress for `flexnetos_github_app` (ADR-0008 §1).
//!
//! P0 surface: `GET /health` and `POST /webhook`. The webhook handler reads the **raw**
//! body, verifies `X-Hub-Signature-256` (constant-time) via `app_core::webhook`, and
//! acks. Routing/dispatch (P2), envctl token minting (P1) and the merge-gate (P3) build
//! on `app-core`'s typed seams. Binds to localhost by design — expose via a tunnel
//! (cloudflared/smee), never a public listener (ADR-0008 §4).

use std::net::SocketAddr;
use std::sync::Arc;

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
    let state = AppState {
        webhook_secret: Arc::new(secret),
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
        .unwrap_or("");
    tracing::info!(event, delivery, kind = ?EventKind::parse(event), "accepted webhook");
    // P2: dedup on the delivery GUID, parse the payload, `router::route()` → signed
    // dispatch to flexnetos_runner over UDS.
    StatusCode::ACCEPTED
}
