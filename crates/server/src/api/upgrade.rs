use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
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

    // `upgrade_available` stays false even for a sensor that reports an older
    // version, because `sha256` below is a placeholder and the agent verifies
    // the digest before swapping its binary. Advertising the upgrade today
    // would only make every sensor download an artifact it must then refuse.
    // Turn it on in the same change that serves a real checksum.
    (
        StatusCode::OK,
        Json(json!({
            "version": current,
            "sensor_version": params.version,
            "outdated": params.version != current,
            "url": format!("/api/v1/upgrade/download/{}", current),
            "sha256": "placeholder-sha256-for-current-version",
            "channel": channel,
            "upgrade_available": false,
        })),
    )
}

async fn download_binary(Path(version): Path<String>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": format!("Binary for version '{}' not available on this server", version),
        })),
    )
}
