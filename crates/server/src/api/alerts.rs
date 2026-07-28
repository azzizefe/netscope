use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{require, Claims};
use crate::db::models::{AlertFilter, UpdateAlertStatus};
use crate::db::queries;

/// Changing an alert's status is triage, not viewing — a `viewer` must not be
/// able to close an alert it is only meant to see.
pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(
            "/",
            get(list_alerts).route_layer(from_fn(require("alerts:read"))),
        )
        .route(
            "/{id}/status",
            patch(update_alert_status).route_layer(from_fn(require("alerts:write"))),
        )
        .with_state(state)
}

async fn list_alerts(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<AlertQueryParams>,
) -> impl IntoResponse {
    let filter = AlertFilter {
        status: params.status,
        severity: params.severity,
        sensor_id: params.sensor_id,
        timerange_start: params.timerange_start,
        timerange_end: params.timerange_end,
        page: params.page,
        per_page: params.per_page,
    };

    match queries::list_alerts(&state.pool, &filter).await {
        Ok(alerts) => (StatusCode::OK, Json(json!(alerts))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn update_alert_status(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(body): Json<UpdateAlertStatus>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    match queries::update_alert_status(&state.pool, id, &body.status, user_id).await {
        Ok(Some(alert)) => (StatusCode::OK, Json(json!(alert))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "alert not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AlertQueryParams {
    status: Option<String>,
    severity: Option<String>,
    sensor_id: Option<Uuid>,
    timerange_start: Option<chrono::DateTime<chrono::Utc>>,
    timerange_end: Option<chrono::DateTime<chrono::Utc>>,
    page: Option<i64>,
    per_page: Option<i64>,
}
