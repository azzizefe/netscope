use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::ws::WsState;

pub fn routes() -> Router {
    Router::new().route("/health", get(health_check))
}

/// `ws` is optional because the extension is layered on outside this router.
/// A missing one must not turn the endpoint a load balancer polls into a 500 —
/// the server is up either way, so the count is simply omitted.
async fn health_check(ws: Option<Extension<Arc<WsState>>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": "netscope-server",
            "version": env!("CARGO_PKG_VERSION"),
            "websocket_sessions": ws.map(|Extension(s)| s.session_count()),
        })),
    )
        .into_response()
}
