use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;

use crate::api::ApiState;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/upgrade/check", get(upgrade_check))
        .route("/upgrade/download/{version}", get(download_binary))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct UpgradeQuery {
    version: String,
    channel: Option<String>,
}

async fn upgrade_check(
    State(_state): State<Arc<ApiState>>,
    Query(params): Query<UpgradeQuery>,
) -> impl IntoResponse {
    let current = env!("CARGO_PKG_VERSION");
    let channel = params.channel.as_deref().unwrap_or("stable");

    (StatusCode::OK, Json(json!({
        "version": current,
        "url": format!("/api/v1/upgrade/download/{}", current),
        "sha256": "placeholder-sha256-for-current-version",
        "channel": channel,
        "upgrade_available": false,
    })))
}

async fn download_binary(
    Path(version): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({
        "error": format!("Binary for version '{}' not available on this server", version),
    })))
}
