use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::api::ApiState;
use crate::auth::require;
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(
            "/summary",
            get(dashboard_summary).route_layer(from_fn(require("dashboard:read"))),
        )
        .with_state(state)
}

/// Cached for [`SUMMARY_TTL_SECS`] when Redis is configured.
///
/// This is the one endpoint worth caching: every open dashboard polls it, it
/// aggregates across the whole events table, and each caller gets the identical
/// answer. The window is deliberately short — a summary that lags a quarter of
/// a minute is fine, one that lags five is misleading during an incident.
const SUMMARY_CACHE_KEY: &str = "dashboard:summary";
const SUMMARY_TTL_SECS: u64 = 15;

async fn dashboard_summary(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    if let Some(cache) = state.cache.as_ref() {
        // A cache miss, an unreachable Redis and a corrupt entry are all the
        // same thing here: fall through to the database.
        if let Ok(Some(hit)) = cache.get::<String>(SUMMARY_CACHE_KEY).await {
            if let Ok(cached) = serde_json::from_str::<serde_json::Value>(&hit) {
                return (StatusCode::OK, Json(cached)).into_response();
            }
        }
    }

    match queries::dashboard_summary(&state.pool).await {
        Ok(summary) => {
            let body = json!(summary);
            if let Some(cache) = state.cache.as_ref() {
                if let Ok(encoded) = serde_json::to_string(&body) {
                    if let Err(e) = cache
                        .set_ttl(SUMMARY_CACHE_KEY, encoded, SUMMARY_TTL_SECS)
                        .await
                    {
                        tracing::warn!("Failed to cache dashboard summary: {e}");
                    }
                }
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
