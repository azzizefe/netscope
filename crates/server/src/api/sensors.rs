use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::db::models::RegisterSensor;
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(list_sensors).post(register_sensor))
        .route("/register", post(register_sensor))
        .route("/{id}", get(get_sensor))
        .route("/{id}/command", post(sensor_command))
        .with_state(state)
}

async fn list_sensors(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    match queries::list_sensors(&state.pool).await {
        Ok(sensors) => (StatusCode::OK, Json(json!(sensors))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn register_sensor(
    State(state): State<Arc<ApiState>>,
    Json(sensor): Json<RegisterSensor>,
) -> impl IntoResponse {
    match queries::register_sensor(&state.pool, &sensor).await {
        Ok(s) => (StatusCode::CREATED, Json(json!(s))).into_response(),
        Err(e) => {
            if e.to_string().contains("unique") {
                return (StatusCode::CONFLICT, Json(json!({"error": "sensor already registered"}))).into_response();
            }
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn get_sensor(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => (StatusCode::OK, Json(json!(s))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "sensor not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn sensor_command(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(cmd): Json<serde_json::Value>,
) -> impl IntoResponse {
    let sensor = match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "sensor not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    tracing::info!("Command for sensor {} ({}): {:?}", sensor.hostname, id, cmd);

    (StatusCode::ACCEPTED, Json(json!({
        "status": "queued",
        "sensor_id": id,
        "command": cmd,
    }))).into_response()
}
