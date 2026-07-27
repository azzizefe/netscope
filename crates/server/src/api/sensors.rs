use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::db::models::{RegisterSensor, SensorHeartbeat};
use crate::db::queries;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommand {
    pub id: Uuid,
    pub command: String,
    pub parameters: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResultReport {
    pub command_id: Uuid,
    pub status: String,
    pub output: Option<String>,
}

pub struct CommandStore {
    pub queues: dashmap::DashMap<Uuid, Vec<PendingCommand>>,
}

impl CommandStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { queues: dashmap::DashMap::new() })
    }

    pub fn push(&self, sensor_id: Uuid, command: String, parameters: serde_json::Value) -> PendingCommand {
        let cmd = PendingCommand {
            id: Uuid::new_v4(),
            command,
            parameters,
            created_at: Utc::now().to_rfc3339(),
        };
        self.queues.entry(sensor_id).or_default().push(cmd.clone());
        cmd
    }

    pub fn drain(&self, sensor_id: Uuid) -> Vec<PendingCommand> {
        self.queues.remove(&sensor_id).map(|(_, v)| v).unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn remove(&self, sensor_id: Uuid, cmd_id: Uuid) -> bool {
        if let Some(mut queue) = self.queues.get_mut(&sensor_id) {
            let len_before = queue.len();
            queue.retain(|c| c.id != cmd_id);
            queue.len() < len_before
        } else {
            false
        }
    }
}

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(list_sensors).post(register_sensor))
        .route("/register", post(register_sensor))
        .route("/{id}", get(get_sensor))
        .route("/{id}/heartbeat", put(sensor_heartbeat))
        .route("/{id}/command", post(sensor_command))
        .route("/{id}/commands", get(poll_commands))
        .route("/{id}/commands/{cmd_id}/result", put(command_result))
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

async fn sensor_heartbeat(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(hb): Json<SensorHeartbeatPayload>,
) -> impl IntoResponse {
    let sensor = match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "sensor not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let db_hb = SensorHeartbeat {
        id: 0,
        sensor_id: id,
        cpu_load_pct: Some(hb.cpu_load_pct),
        ram_used_mb: Some(hb.ram_used_mb),
        capture_throughput_bps: Some(hb.capture_throughput_bps),
        uptime_secs: Some(hb.uptime_secs),
        interface_stats: None,
        received_at: Utc::now(),
    };

    match queries::update_sensor_heartbeat(&state.pool, id, &db_hb).await {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok", "sensor_id": id, "hostname": sensor.hostname}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SensorHeartbeatPayload {
    pub cpu_load_pct: f32,
    pub ram_used_mb: i32,
    pub capture_throughput_bps: i64,
    pub disk_free_mb: i64,
    pub uptime_secs: i64,
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

    let command_name = cmd.get("command").and_then(|v| v.as_str()).unwrap_or("unknown");
    let parameters = cmd.get("parameters").cloned().unwrap_or(json!({}));

    let pc = state.commands.push(id, command_name.to_string(), parameters);

    tracing::info!("Command queued for sensor {} ({}): {} [{}]", sensor.hostname, id, command_name, pc.id);

    (StatusCode::ACCEPTED, Json(json!({
        "status": "queued",
        "command_id": pc.id,
        "sensor_id": id,
        "command": command_name,
    }))).into_response()
}

async fn poll_commands(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let _sensor = match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "sensor not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let commands = state.commands.drain(id);

    (StatusCode::OK, Json(json!(commands))).into_response()
}

async fn command_result(
    State(_state): State<Arc<ApiState>>,
    Path((id, cmd_id)): Path<(Uuid, Uuid)>,
    Json(result): Json<CommandResultReport>,
) -> impl IntoResponse {
    tracing::info!(
        "Command result for sensor {} cmd {}: {}",
        id, cmd_id, result.status
    );

    (StatusCode::OK, Json(json!({
        "status": "acknowledged",
        "command_id": cmd_id,
    }))).into_response()
}
