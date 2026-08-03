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
    pub deployment_type: String,
    pub capture_mode: String,
    pub location: Option<String>,
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
    #[serde(default = "default_deployment_type")]
    pub deployment_type: String,
    #[serde(default = "default_capture_mode")]
    pub capture_mode: String,
    pub location: Option<String>,
}

fn default_deployment_type() -> String {
    "endpoint".to_string()
}
fn default_capture_mode() -> String {
    "passive".to_string()
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
    pub os: Option<String>,
    pub version: String,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub uptime_secs: Option<i64>,
    pub cpu_load_pct: Option<f32>,
    pub ram_used_mb: Option<i32>,
    pub ram_mb: Option<i32>,
    pub capture_throughput_bps: Option<i64>,
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
    pub assigned_to: Option<Uuid>,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetail {
    pub alert: Alert,
    pub rule_name: Option<String>,
    pub rule_description: Option<String>,
    pub rule_yaml: Option<String>,
    pub event_details: Option<serde_json::Value>,
    pub assigned_username: Option<String>,
    pub acknowledged_username: Option<String>,
    pub resolved_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AlertNote {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub note: String,
    pub created_at: DateTime<Utc>,
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
    pub assigned_to: Option<Uuid>,
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

    // New Metrics
    pub total_events_24h: i64,
    pub open_alerts_l1: i64,
    pub open_alerts_l2: i64,
    pub open_alerts_l3: i64,
    pub alert_trend_1h: Vec<i64>,
    pub top_attackers_5: Vec<IpCount>,
    pub top_targets_5: Vec<IpCount>,
    pub protocol_distribution: Vec<ProtocolCount>,
    pub aggregate_throughput_bps: i64,
    pub mttr_seconds_7d: f64,
    pub false_positive_rate_7d: f64,
}

#[derive(Debug, Serialize, sqlx::FromRow, Clone)]
pub struct IpCount {
    pub ip: String,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow, Clone)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: i64,
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

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ThroughputPoint {
    pub minute: DateTime<Utc>,
    pub throughput: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TopologyEdge {
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub count: i64,
}

// ── Threat Hunting ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HuntRule {
    Group {
        logical: String,
        rules: Vec<HuntRule>,
    },
    Condition {
        field: String,
        operator: String,
        value: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntQueryPayload {
    pub filter: Option<HuntRule>,
    pub timerange_start: Option<DateTime<Utc>>,
    pub timerange_end: Option<DateTime<Utc>>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramPayload {
    pub filter: Option<HuntRule>,
    pub timerange_start: Option<DateTime<Utc>>,
    pub timerange_end: Option<DateTime<Utc>>,
    pub bucket_size_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HistogramBucket {
    pub bucket_time: DateTime<Utc>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SavedSearch {
    pub id: Uuid,
    pub name: String,
    pub query_json: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSavedSearch {
    pub name: String,
    pub query_json: serde_json::Value,
}

// ── Reporting & Scheduling ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScheduledReport {
    pub id: Uuid,
    pub report_type: String,
    pub recipients: String,
    pub schedule: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScheduledReport {
    pub report_type: String,
    pub recipients: String,
    pub schedule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySocReport {
    pub total_events: i64,
    pub total_alerts: i64,
    pub alerts_by_severity: std::collections::HashMap<String, i64>,
    pub resolved_alerts: i64,
    pub false_positive_alerts: i64,
    pub top_sensors: Vec<CountByEntity>,
    pub top_rules: Vec<CountByEntity>,
    pub new_ips: Vec<String>,
    pub new_protocols: Vec<String>,
    pub mttr_seconds: f64,
    pub mean_ack_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CountByEntity {
    pub name: String,
    pub count: i64,
}

/// What netscope can say about a deployment's compliance posture.
///
/// Every score is optional, and `None` is a real answer: it means netscope did
/// not measure this, either because the framework asks about something that
/// does not appear in network telemetry, or because there was no data in the
/// window to measure. The alternative is what this struct used to do — return
/// `f64` and fill the gaps with 94.5, 89.0, 92.0 and 90.0, invented constants
/// with one decimal place, which the dashboard then drew as green bars. A score
/// nobody computed must not be renderable as a score.
///
/// The scores that do exist are narrow proxies, not audits: an acknowledgement
/// SLA is evidence *towards* ISO 27001 A.5.25, not a verdict on the standard.
/// `*_details` says which measurement was taken and over how many samples, so a
/// 100% drawn from three alerts cannot be read as a 100% drawn from thirty
/// thousand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Mean of the scores that were actually measured; `None` if none were.
    pub overall_score: Option<f64>,
    /// Not measured. Whether personal data is processed lawfully is not
    /// visible in packet headers.
    pub gdpr_score: Option<f64>,
    pub gdpr_details: String,
    /// Not measured, for the same reason as `gdpr_score`.
    pub kvkk_score: Option<f64>,
    pub kvkk_details: String,
    pub iso27001_score: Option<f64>,
    pub iso27001_details: String,
    pub pci_dss_score: Option<f64>,
    pub pci_dss_details: String,
    pub nis2_score: Option<f64>,
    pub nis2_details: String,
    pub generated_at: DateTime<Utc>,
}

// ── SOAR & Incident Response ──

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Case {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub severity: String,
    pub assigned_to: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCase {
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub alert_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Evidence {
    pub id: Uuid,
    pub case_id: Uuid,
    pub evidence_type: String,
    pub filename: String,
    pub filepath: String,
    pub added_by: Option<Uuid>,
    pub added_at: DateTime<Utc>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ChainOfCustody {
    pub id: Uuid,
    pub evidence_id: Uuid,
    pub action: String,
    pub performed_by: Option<Uuid>,
    pub performed_at: DateTime<Utc>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IncidentTimeline {
    pub id: Uuid,
    pub case_id: Uuid,
    pub event_type: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub actor: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TicketingIntegration {
    pub id: Uuid,
    pub provider: String,
    pub url: String,
    pub api_token: Option<String>,
    pub project_key: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketingIntegration {
    pub provider: String,
    pub url: String,
    pub api_token: Option<String>,
    pub project_key: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DbPlaybook {
    pub id: Uuid,
    pub name: String,
    pub yaml_content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePlaybook {
    pub name: String,
    pub yaml_content: String,
}
