use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ── Users ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip)]
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

// A `UserResponse` (the `User` row minus `password_hash`) and its `From<User>`
// used to sit here, together with `get_user_by_id` in queries.rs. Nothing
// constructed either: they are the parts of a `GET /api/v1/auth/me` that was
// never written. Bring them back with that endpoint — a serialisable user
// projection has no other purpose, and leaving it here only made it look as
// though the route existed.

// ── Sensors ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Sensor {
    pub id: Uuid,
    pub hostname: String,
    pub ip_address: String,
    pub os: Option<String>,
    pub version: String,
    pub interfaces: serde_json::Value,
    pub cpu_cores: Option<i32>,
    pub ram_mb: Option<i32>,
    pub status: String,
    pub tags: serde_json::Value,
    pub metadata: serde_json::Value,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterSensor {
    pub hostname: String,
    pub ip_address: String,
    pub os: Option<String>,
    pub version: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub cpu_cores: Option<i32>,
    pub ram_mb: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct SensorSummary {
    pub id: Uuid,
    pub hostname: String,
    pub ip_address: String,
    pub version: String,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub uptime_secs: Option<i64>,
    pub cpu_load_pct: Option<f32>,
}

// ── Heartbeats ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensorHeartbeat {
    pub id: i64,
    pub sensor_id: Uuid,
    pub cpu_load_pct: Option<f32>,
    pub ram_used_mb: Option<i32>,
    pub capture_throughput_bps: Option<i64>,
    pub uptime_secs: Option<i64>,
    pub disk_free_mb: Option<i64>,
    pub interface_stats: Option<serde_json::Value>,
    pub received_at: DateTime<Utc>,
}

// ── Events ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Event {
    pub id: Uuid,
    pub sensor_id: Option<Uuid>,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub raw_data: Option<serde_json::Value>,
    pub tags: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EventFilter {
    pub severity: Option<String>,
    pub sensor_id: Option<Uuid>,
    pub timerange_start: Option<DateTime<Utc>>,
    pub timerange_end: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

// ── Alerts ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: Option<Uuid>,
    pub sensor_id: Option<Uuid>,
    pub event_id: Option<Uuid>,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub raw_data: Option<serde_json::Value>,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AlertFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub sensor_id: Option<Uuid>,
    pub timerange_start: Option<DateTime<Utc>>,
    pub timerange_end: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertStatus {
    pub status: String,
}

// ── Alert Rules ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AlertRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub severity: String,
    pub condition: serde_json::Value,
    pub actions: serde_json::Value,
    pub cooldown_secs: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRule {
    pub name: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub severity: Option<String>,
    pub condition: serde_json::Value,
    pub actions: Option<serde_json::Value>,
    pub cooldown_secs: Option<i32>,
}

// ── Dashboard ──

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub active_alerts: i64,
    pub events_per_second: f64,
    pub total_sensors: i64,
    pub online_sensors: i64,
    pub top_talkers: Vec<TopTalker>,
    pub top_threats: Vec<TopThreat>,
    pub alerts_by_severity: Vec<CountBySeverity>,
}

#[derive(Debug, Serialize)]
pub struct TopTalker {
    pub ip: String,
    pub bytes: i64,
    pub packets: i64,
}

#[derive(Debug, Serialize, FromRow)]
pub struct TopThreat {
    pub indicator_type: String,
    pub value: String,
    pub confidence: String,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct CountBySeverity {
    pub severity: String,
    pub count: i64,
}

// ── Roles / Permissions ──
//
// There is no `Role` row model here on purpose. Permissions live in
// `RbacState::new()` as a compiled-in table, not in the database, so a model
// for the `roles` table described something nothing reads or writes. If roles
// ever become editable at runtime, the model comes back with the queries that
// use it.

// ── Sensor Configuration ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensorConfig {
    pub sensor_id: Uuid,
    pub config_data: String,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensorConfigHistory {
    pub id: Uuid,
    pub sensor_id: Uuid,
    pub config_data: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

