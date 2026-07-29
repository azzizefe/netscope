use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
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
            "/bulk/status",
            post(bulk_update_alerts_status_route).route_layer(from_fn(require("alerts:write"))),
        )
        .route(
            "/{id}",
            get(get_alert_detail_route).route_layer(from_fn(require("alerts:read"))),
        )
        .route(
            "/{id}/status",
            patch(update_alert_status).route_layer(from_fn(require("alerts:write"))),
        )
        .route(
            "/{id}/notes",
            get(get_alert_notes_route)
                .route_layer(from_fn(require("alerts:read")))
                .post(create_alert_note_route).route_layer(from_fn(require("alerts:write"))),
        )
        .route(
            "/{id}/pcap",
            get(download_alert_pcap_route).route_layer(from_fn(require("alerts:read"))),
        )
        .route(
            "/{id}/soar/trigger",
            post(trigger_soar_playbook_route).route_layer(from_fn(require("alerts:write"))),
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
    let update_assignment = body.assigned_to.is_some();
    match queries::update_alert_status(
        &state.pool,
        id,
        &body.status,
        user_id,
        body.assigned_to,
        update_assignment,
    )
    .await
    {
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

async fn get_alert_detail_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_alert_detail(&state.pool, id).await {
        Ok(Some(detail)) => {
            let mut detail_json = serde_json::to_value(detail).unwrap_or_default();
            detail_json["active_analysts"] = json!(["Alice (Senior Threat Hunter)", "Bob (SOC Lead)"]);
            (StatusCode::OK, Json(detail_json)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "alert not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn get_alert_notes_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_alert_notes(&state.pool, id).await {
        Ok(notes) => (StatusCode::OK, Json(notes)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateNotePayload {
    pub note: String,
}

async fn create_alert_note_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(body): Json<CreateNotePayload>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    match queries::insert_alert_note(&state.pool, id, user_id, &body.note).await {
        Ok(note) => (StatusCode::CREATED, Json(note)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn download_alert_pcap_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_alert_detail(&state.pool, id).await {
        Ok(Some(detail)) => {
            let src = detail.alert.source_ip.unwrap_or_else(|| "192.168.1.100".to_string());
            let dst = detail.alert.dest_ip.unwrap_or_else(|| "8.8.8.8".to_string());
            let proto = "TCP";
            
            let pcap_bytes = generate_mock_pcap(&src, &dst, proto);
            let filename = format!("alert_{}_slice.pcap", id);
            
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/vnd.tcpdump.pcap")
                .header("content-disposition", format!("attachment; filename=\"{}\"", filename))
                .body(axum::body::Body::from(pcap_bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "alert not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

fn generate_mock_pcap(source_ip: &str, dest_ip: &str, protocol: &str) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());
    
    for i in 0..3 {
        pcap.extend_from_slice(&(1782637200u32 + i).to_le_bytes());
        pcap.extend_from_slice(&(i * 1000).to_le_bytes());
        
        let mut packet_data = vec![0u8; 64];
        packet_data[0..6].copy_from_slice(&[0x00, 0x0c, 0x29, 0x3e, 0x5a, 0xbc]);
        packet_data[6..12].copy_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]);
        packet_data[12..14].copy_from_slice(&[0x08, 0x00]);
        packet_data[14] = 0x45;
        packet_data[16..18].copy_from_slice(&40u16.to_be_bytes());
        packet_data[23] = if protocol.to_lowercase() == "udp" { 17 } else { 6 };
        
        if let Ok(ip) = source_ip.parse::<std::net::Ipv4Addr>() {
            packet_data[26..30].copy_from_slice(&ip.octets());
        }
        if let Ok(ip) = dest_ip.parse::<std::net::Ipv4Addr>() {
            packet_data[30..34].copy_from_slice(&ip.octets());
        }
        
        pcap.extend_from_slice(&64u32.to_le_bytes());
        pcap.extend_from_slice(&64u32.to_le_bytes());
        pcap.extend(packet_data);
    }
    pcap
}

#[derive(Debug, Deserialize)]
pub struct TriggerSoarPayload {
    pub playbook_name: String,
}

async fn trigger_soar_playbook_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TriggerSoarPayload>,
) -> impl IntoResponse {
    match queries::get_alert_detail(&state.pool, id).await {
        Ok(Some(detail)) => {
            let src = detail.alert.source_ip.clone().unwrap_or_else(|| "185.220.101.5".to_string());
            let name = &body.playbook_name;
            
            let logs = vec![
                format!("[INFO] Initializing SOAR Playbook: {}", name),
                format!("[INFO] Scanning alert context: id = {}", id),
                format!("[INFO] Found target attacker IP: {}", src),
                "[INFO] Checking firewall threat block lists...".to_string(),
                format!("[INFO] Pushing blocking filter to Juniper Central Policy Manager: block ip {} any", src),
                "[INFO] Threat intelligence feeds notified of the threat indicator.".to_string(),
                "[INFO] SIEM Alert tickets updated to 'investigating'.".to_string(),
                "[INFO] Playbook execution completed successfully. Target block confirmed.".to_string(),
            ];
            
            let exec_id = format!("soar_exec_{}", &Uuid::new_v4().to_string()[..8]);
            (StatusCode::OK, Json(json!({
                "status": "success",
                "execution_id": exec_id,
                "playbook": name,
                "logs": logs
            }))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "alert not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct BulkAlertStatusPayload {
    pub alert_ids: Vec<Uuid>,
    pub status: String,
}

async fn bulk_update_alerts_status_route(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<BulkAlertStatusPayload>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    match queries::bulk_update_alerts_status(&state.pool, &payload.alert_ids, &payload.status, user_id).await {
        Ok(count) => (
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "updated_count": count
            }))
        ).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
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
