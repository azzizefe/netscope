use std::sync::Arc;

use axum::extract::{Path, State, Extension};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::ws::SensorWsRegistry;
use crate::api::sensors_config::validate_and_canonicalize;

use crate::api::ApiState;
use crate::auth::require;
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
        Arc::new(Self {
            queues: dashmap::DashMap::new(),
        })
    }

    pub fn push(
        &self,
        sensor_id: Uuid,
        command: String,
        parameters: serde_json::Value,
    ) -> PendingCommand {
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
        self.queues
            .remove(&sensor_id)
            .map(|(_, v)| v)
            .unwrap_or_default()
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

/// Permissions are attached per method, not per route group.
///
/// `GET /` and `POST /` share a path but not a privilege level, so a single
/// group-wide layer has to pick one of them — and picking the read permission
/// is what let a `viewer` token register sensors and command the fleet.
pub fn routes(state: Arc<ApiState>) -> Router {
    let read = || from_fn(require("sensors:read"));
    let write = || from_fn(require("sensors:write"));

    Router::new()
        .route(
            "/",
            get(list_sensors)
                .route_layer(read())
                .merge(post(register_sensor).route_layer(write())),
        )
        .route("/register", post(register_sensor).route_layer(write()))
        .route("/{id}", get(get_sensor).route_layer(read()))
        .route(
            "/{id}/heartbeat",
            put(sensor_heartbeat).route_layer(write()),
        )
        // Issuing a command is its own privilege: it makes a remote sensor act,
        // which is not the same authority as editing its record.
        .route(
            "/{id}/command",
            post(sensor_command).route_layer(from_fn(require("sensors:command"))),
        )
        // The agent side of the command loop — draining its own queue and
        // reporting the outcome.
        .route("/{id}/commands", get(poll_commands).route_layer(read()))
        .route(
            "/{id}/commands/{cmd_id}/result",
            put(command_result).route_layer(write()),
        )
        .route(
            "/{id}/config",
            get(get_sensor_config_route)
                .route_layer(read())
                .merge(put(update_sensor_config_route).route_layer(write())),
        )
        .route(
            "/{id}/config/history",
            get(get_sensor_config_history_route).route_layer(read()),
        )
        .route(
            "/{id}/config/rollback",
            post(rollback_sensor_config_route).route_layer(write()),
        )
        .route(
            "/{id}/ws",
            get(sensor_ws_handler),
        )
        .with_state(state)
}

async fn list_sensors(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    match queries::list_sensors(&state.pool).await {
        Ok(sensors) => (StatusCode::OK, Json(json!(sensors))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
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
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "sensor already registered"})),
                )
                    .into_response();
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn get_sensor(State(state): State<Arc<ApiState>>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let cached_hb = if let Some(ref cache) = state.cache {
        let key = format!("sensor:heartbeat:{}", id);
        cache.get::<String>(&key).await.ok().flatten()
    } else {
        None
    };

    match queries::get_sensor(&state.pool, id).await {
        Ok(Some(mut s)) => {
            if cached_hb.is_some() {
                s.status = "online".into();
            }
            (StatusCode::OK, Json(json!(s))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "sensor not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn sensor_heartbeat(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(hb): Json<SensorHeartbeatPayload>,
) -> impl IntoResponse {
    let sensor = match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "sensor not found"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let db_hb = SensorHeartbeat {
        id: 0,
        sensor_id: id,
        cpu_load_pct: Some(hb.cpu_load_pct),
        ram_used_mb: Some(hb.ram_used_mb),
        capture_throughput_bps: Some(hb.capture_throughput_bps),
        uptime_secs: Some(hb.uptime_secs),
        disk_free_mb: Some(hb.disk_free_mb),
        interface_stats: None,
        received_at: Utc::now(),
    };

    match queries::update_sensor_heartbeat(&state.pool, id, &db_hb).await {
        Ok(_) => {
            if let Some(ref cache) = state.cache {
                let key = format!("sensor:heartbeat:{}", id);
                let hb_str = serde_json::to_string(&hb).unwrap_or_default();
                let _ = cache.set_ttl(&key, hb_str, 60).await;
            }
            (
                StatusCode::OK,
                Json(json!({"status": "ok", "sensor_id": id, "hostname": sensor.hostname})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "sensor not found"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let command_name = cmd
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let parameters = cmd.get("parameters").cloned().unwrap_or(json!({}));

    let pc = state
        .commands
        .push(id, command_name.to_string(), parameters);

    tracing::info!(
        "Command queued for sensor {} ({}): {} [{}]",
        sensor.hostname,
        id,
        command_name,
        pc.id
    );

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "queued",
            "command_id": pc.id,
            "sensor_id": id,
            "command": command_name,
        })),
    )
        .into_response()
}

async fn poll_commands(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let _sensor = match queries::get_sensor(&state.pool, id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "sensor not found"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
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
        id,
        cmd_id,
        result.status
    );

    (
        StatusCode::OK,
        Json(json!({
            "status": "acknowledged",
            "command_id": cmd_id,
        })),
    )
        .into_response()
}

// ── Sensor Config Route Handlers ──

async fn get_sensor_config_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor_config(&state.pool, id).await {
        Ok(Some(cfg)) => (StatusCode::OK, Json(cfg)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "No config found for this sensor"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigPayload {
    pub config_data: String,
}

async fn update_sensor_config_route(
    State(state): State<Arc<ApiState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Extension(ws_registry): Extension<Arc<SensorWsRegistry>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateConfigPayload>,
) -> impl IntoResponse {
    let canonicalized_toml = match validate_and_canonicalize(&payload.config_data) {
        Ok(toml) => toml,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    };

    let config = match queries::update_sensor_config(&state.pool, id, &canonicalized_toml, Some(claims.sub)).await {
        Ok(cfg) => cfg,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let details = json!({
        "version": config.version,
        "config_len": config.config_data.len()
    });
    if let Err(e) = queries::insert_audit_log(&state.pool, Some(claims.sub), "config_update", "sensor_config", Some(id), details).await {
        tracing::error!("Failed to write to audit log: {}", e);
    }

    let pushed = ws_registry.push_config(id, &config.config_data);
    tracing::info!("Pushed config to sensor {} (version {}): success={}", id, config.version, pushed);

    (StatusCode::OK, Json(config)).into_response()
}

async fn get_sensor_config_history_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor_config_history(&state.pool, id).await {
        Ok(history) => (StatusCode::OK, Json(history)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct RollbackPayload {
    pub version: i32,
}

async fn rollback_sensor_config_route(
    State(state): State<Arc<ApiState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Extension(ws_registry): Extension<Arc<SensorWsRegistry>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<RollbackPayload>,
) -> impl IntoResponse {
    let historical = match queries::get_sensor_config_version(&state.pool, id, payload.version).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "Config version not found"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let config = match queries::update_sensor_config(&state.pool, id, &historical.config_data, Some(claims.sub)).await {
        Ok(cfg) => cfg,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let details = json!({
        "rolled_back_to_version": historical.version,
        "new_version": config.version
    });
    if let Err(e) = queries::insert_audit_log(&state.pool, Some(claims.sub), "config_rollback", "sensor_config", Some(id), details).await {
        tracing::error!("Failed to write to audit log: {}", e);
    }

    let pushed = ws_registry.push_config(id, &config.config_data);
    tracing::info!("Pushed rolled-back config to sensor {} (version {}): success={}", id, config.version, pushed);

    (StatusCode::OK, Json(config)).into_response()
}

// ── Sensor WebSocket Upgrade Route ──

async fn sensor_ws_handler(
    ws: WebSocketUpgrade,
    Path(id): Path<Uuid>,
    Extension(ws_registry): Extension<Arc<SensorWsRegistry>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_sensor_ws(socket, id, ws_registry))
}

async fn handle_sensor_ws(
    mut socket: WebSocket,
    sensor_id: Uuid,
    ws_registry: Arc<SensorWsRegistry>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    ws_registry.register(sensor_id, tx);
    tracing::info!("Sensor WS connected: {}", sensor_id);

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(m) => {
                        if socket.send(m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    ws_registry.unregister(sensor_id);
    tracing::info!("Sensor WS disconnected: {}", sensor_id);
}
