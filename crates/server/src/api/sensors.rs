use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::sensors_config::validate_and_canonicalize;
use crate::ws::SensorWsRegistry;

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
        .route(
            "/bulk/command",
            post(bulk_sensor_command).route_layer(from_fn(require("sensors:command"))),
        )
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
            "/{id}/throughput",
            get(sensor_throughput_history_route).route_layer(read()),
        )
        .route("/{id}/logs", get(sensor_logs_route).route_layer(read()))
        .route(
            "/{id}/topology",
            get(sensor_topology_route).route_layer(read()),
        )
        .route("/{id}/ws", get(sensor_ws_handler))
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
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No config found for this sensor"})),
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

    let config =
        match queries::update_sensor_config(&state.pool, id, &canonicalized_toml, Some(claims.sub))
            .await
        {
            Ok(cfg) => cfg,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        };

    let details = json!({
        "version": config.version,
        "config_len": config.config_data.len()
    });
    if let Err(e) = queries::insert_audit_log(
        &state.pool,
        Some(claims.sub),
        "config_update",
        "sensor_config",
        Some(id),
        details,
    )
    .await
    {
        tracing::error!("Failed to write to audit log: {}", e);
    }

    let pushed = ws_registry.push_config(id, &config.config_data);
    tracing::info!(
        "Pushed config to sensor {} (version {}): success={}",
        id,
        config.version,
        pushed
    );

    (StatusCode::OK, Json(config)).into_response()
}

async fn get_sensor_config_history_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor_config_history(&state.pool, id).await {
        Ok(history) => (StatusCode::OK, Json(history)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
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
    let historical =
        match queries::get_sensor_config_version(&state.pool, id, payload.version).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Config version not found"})),
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

    let config = match queries::update_sensor_config(
        &state.pool,
        id,
        &historical.config_data,
        Some(claims.sub),
    )
    .await
    {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let details = json!({
        "rolled_back_to_version": historical.version,
        "new_version": config.version
    });
    if let Err(e) = queries::insert_audit_log(
        &state.pool,
        Some(claims.sub),
        "config_rollback",
        "sensor_config",
        Some(id),
        details,
    )
    .await
    {
        tracing::error!("Failed to write to audit log: {}", e);
    }

    let pushed = ws_registry.push_config(id, &config.config_data);
    tracing::info!(
        "Pushed rolled-back config to sensor {} (version {}): success={}",
        id,
        config.version,
        pushed
    );

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

// ── Sensor Telemetry, Logs, Topology, and Bulk command handlers ──

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
}

async fn sensor_logs_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Query(params): Query<LogsQuery>,
) -> impl IntoResponse {
    match queries::get_sensor(&state.pool, id).await {
        Ok(Some(sensor)) => {
            let limit = params.limit.unwrap_or(100).min(1000);
            let since = params
                .since
                .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(1));

            let mut logs = Vec::new();
            let mut current_time = since;
            let now = chrono::Utc::now();

            let mock_messages = [
                (
                    "INFO",
                    "Packet capture engine initialized on interface eth0.",
                ),
                (
                    "INFO",
                    "Loaded protocol dissectors: TCP, UDP, DNS, HTTP, TLS, J1708.",
                ),
                ("DEBUG", "Acquiring memory-mapped ring buffer lock..."),
                ("INFO", "BPF Filter applied successfully: tcp port 80"),
                (
                    "INFO",
                    "Connected to Netscope Central Server at wss://127.0.0.1:9443/ws.",
                ),
                (
                    "DEBUG",
                    "Sent heartbeat payload: CPU 4.5%, RAM 52%, Uptime 1800s.",
                ),
                (
                    "INFO",
                    "Log rotation triggered by timer. Rotating capture file.",
                ),
                (
                    "INFO",
                    "Capture file closed: /var/log/netscope/capture_active.pcap",
                ),
                (
                    "INFO",
                    "New capture file opened: /var/log/netscope/capture_rotate_1.pcap",
                ),
                (
                    "WARN",
                    "High throughput warning: Interface rx rate exceeded 800 Mbps.",
                ),
                (
                    "ERROR",
                    "DNS parser encountered malformed query header from 10.0.4.15.",
                ),
                (
                    "INFO",
                    "Command received from server: set_filter [id: cmd_123]",
                ),
                ("INFO", "Bpf filter changed to: udp port 53"),
                (
                    "DEBUG",
                    "Garbage collection run complete. Freed 24MB memory-mapped buffer.",
                ),
            ];

            let mut idx = 0;
            while current_time < now && logs.len() < limit {
                let seconds_to_add = (idx * 7 + 11) % 65;
                current_time += chrono::Duration::seconds(seconds_to_add as i64);
                if current_time >= now {
                    break;
                }

                let (level, msg) = mock_messages[idx % mock_messages.len()];
                logs.push(json!({
                    "timestamp": current_time.to_rfc3339(),
                    "level": level,
                    "message": format!("[{}] {}", sensor.hostname, msg)
                }));
                idx += 1;
            }

            (StatusCode::OK, Json(logs)).into_response()
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

async fn sensor_throughput_history_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor_throughput_history(&state.pool, id).await {
        Ok(points) => (StatusCode::OK, Json(points)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn sensor_topology_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_sensor_topology(&state.pool, id).await {
        Ok(edges) => {
            if !edges.is_empty() {
                let mut nodes = std::collections::HashSet::new();
                let mut links = Vec::new();
                for edge in &edges {
                    nodes.insert(edge.source_ip.clone());
                    nodes.insert(edge.dest_ip.clone());
                    links.push(json!({
                        "source": edge.source_ip,
                        "target": edge.dest_ip,
                        "protocol": edge.protocol,
                        "value": edge.count
                    }));
                }
                let nodes_list: Vec<_> = nodes.into_iter().map(|ip| json!({ "id": ip, "group": if ip.starts_with("10.") || ip.starts_with("192.") { 1 } else { 2 } })).collect();
                return (
                    StatusCode::OK,
                    Json(json!({
                        "nodes": nodes_list,
                        "links": links
                    })),
                )
                    .into_response();
            }

            let nodes = vec![
                json!({ "id": "192.168.1.1", "group": 1 }),
                json!({ "id": "192.168.1.10", "group": 1 }),
                json!({ "id": "192.168.1.50", "group": 1 }),
                json!({ "id": "192.168.1.100", "group": 1 }),
                json!({ "id": "192.168.1.101", "group": 1 }),
                json!({ "id": "8.8.8.8", "group": 2 }),
                json!({ "id": "104.244.42.1", "group": 2 }),
            ];

            let links = vec![
                json!({ "source": "192.168.1.10", "target": "192.168.1.1", "protocol": "ARP", "value": 50 }),
                json!({ "source": "192.168.1.100", "target": "192.168.1.1", "protocol": "TCP", "value": 150 }),
                json!({ "source": "192.168.1.101", "target": "192.168.1.1", "protocol": "TCP", "value": 120 }),
                json!({ "source": "192.168.1.100", "target": "192.168.1.50", "protocol": "TCP", "value": 850 }),
                json!({ "source": "192.168.1.101", "target": "192.168.1.50", "protocol": "TCP", "value": 640 }),
                json!({ "source": "192.168.1.100", "target": "8.8.8.8", "protocol": "DNS", "value": 80 }),
                json!({ "source": "192.168.1.101", "target": "8.8.8.8", "protocol": "DNS", "value": 95 }),
                json!({ "source": "192.168.1.100", "target": "104.244.42.1", "protocol": "HTTPS", "value": 310 }),
                json!({ "source": "192.168.1.10", "target": "192.168.1.50", "protocol": "UDP", "value": 140 }),
            ];

            (
                StatusCode::OK,
                Json(json!({
                    "nodes": nodes,
                    "links": links
                })),
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

#[derive(Debug, Deserialize)]
pub struct BulkCommandPayload {
    pub sensor_ids: Vec<Uuid>,
    pub command: String,
    pub parameters: serde_json::Value,
}

async fn bulk_sensor_command(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<BulkCommandPayload>,
) -> impl IntoResponse {
    let mut queued_count = 0;
    for sensor_id in payload.sensor_ids {
        state.commands.push(
            sensor_id,
            payload.command.clone(),
            payload.parameters.clone(),
        );
        queued_count += 1;
    }

    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "queued",
            "queued_count": queued_count,
        })),
    )
}
