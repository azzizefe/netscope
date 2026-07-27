use axum::{Json, Router};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::json;

pub fn routes() -> Router {
    Router::new()
        .route("/health", get(health_check))
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({
        "status": "ok",
        "service": "netscope-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))).into_response()
}
