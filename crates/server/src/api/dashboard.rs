use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::json;

use crate::api::ApiState;
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/summary", get(dashboard_summary))
        .with_state(state)
}

async fn dashboard_summary(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    match queries::dashboard_summary(&state.pool).await {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}
