use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::db::models::EventFilter;
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(list_events))
        .with_state(state)
}

async fn list_events(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<EventQueryParams>,
) -> impl IntoResponse {
    let filter = EventFilter {
        severity: params.severity,
        sensor_id: params.sensor_id,
        timerange_start: params.timerange_start,
        timerange_end: params.timerange_end,
        event_type: params.event_type,
        page: params.page,
        per_page: params.per_page,
    };

    match queries::list_events(&state.pool, &filter).await {
        Ok(events) => (StatusCode::OK, Json(json!(events))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct EventQueryParams {
    severity: Option<String>,
    sensor_id: Option<Uuid>,
    timerange_start: Option<chrono::DateTime<chrono::Utc>>,
    timerange_end: Option<chrono::DateTime<chrono::Utc>>,
    event_type: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}
