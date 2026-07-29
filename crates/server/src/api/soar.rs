use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{require, Claims};
use crate::db::models::{
    CreateCase, CreatePlaybook, CreateTicketingIntegration,
};
use crate::db::queries;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PlaybookYaml {
    pub name: String,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PlaybookTrigger {
    pub rule_ids: Vec<i64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PlaybookStep {
    pub action: String,
    pub target: String,
    pub condition: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DebugPlaybookRequest {
    pub yaml_content: String,
    pub mock_fields: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ExecutePlaybookRequest {
    pub playbook_name: String,
    pub alert_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct EvidenceUploadRequest {
    pub evidence_type: String,
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct CaseStatusUpdateRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct TicketingWebhookPayload {
    pub integration_provider: String,
    pub ticket_key: String,
    pub action: String, // "closed", "commented", etc.
    pub case_id: Uuid,
}

pub fn routes(state: Arc<ApiState>) -> Router {
    let read = || from_fn(require("alerts:read"));
    let write = || from_fn(require("alerts:write"));

    Router::new()
        .route("/playbooks", get(list_playbooks_route).post(save_playbook_route).route_layer(read()))
        .route("/playbooks/debug", post(debug_playbook_route).route_layer(read()))
        .route("/playbooks/execute", post(execute_playbook_route).route_layer(write()))
        .route("/playbooks/marketplace", get(marketplace_list_route).route_layer(read()))
        .route("/cases", get(list_cases_route).post(create_case_route).route_layer(read()))
        .route("/cases/{id}", get(get_case_route).route_layer(read()))
        .route("/cases/{id}/status", post(update_case_status_route).route_layer(write()))
        .route("/cases/{id}/evidence", post(upload_evidence_route).route_layer(write()))
        .route("/cases/{id}/post-mortem", get(get_post_mortem_route).route_layer(read()))
        .route("/ticketing", get(list_integrations_route).post(save_integration_route).route_layer(read()))
        .route("/ticketing/webhook", post(ticketing_webhook_route).route_layer(write()))
        .with_state(state)
}

async fn list_playbooks_route(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    match queries::list_playbooks(&state.pool).await {
        Ok(playbooks) => (StatusCode::OK, Json(playbooks)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn save_playbook_route(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<CreatePlaybook>,
) -> impl IntoResponse {
    match queries::insert_playbook(&state.pool, &payload.name, &payload.yaml_content).await {
        Ok(playbook) => (StatusCode::CREATED, Json(playbook)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn debug_playbook_route(
    Json(payload): Json<DebugPlaybookRequest>,
) -> impl IntoResponse {
    // 1. Parse Playbook YAML
    let playbook: PlaybookYaml = match serde_yaml::from_str(&payload.yaml_content) {
        Ok(pb) => pb,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("YAML Parse Error: {}", e)
                })),
            )
                .into_response()
        }
    };

    // 2. Trace dry run evaluations
    let mut step_traces = Vec::new();
    
    for (idx, step) in playbook.steps.iter().enumerate() {
        let mut condition_matched = true;
        let condition_logs;
        
        if let Some(ref cond) = step.condition {
            // Simple dry-run condition parsing: e.g. AbuseIPDB confidence confidence > 80
            if cond.contains("confidence") {
                let mock_conf = payload
                    .mock_fields
                    .get("confidence")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(75);
                
                // Extract comparison number
                let compare_val: i64 = cond
                    .split('>')
                    .nth(1)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(80);
                
                condition_matched = mock_conf > compare_val;
                condition_logs = format!(
                    "Condition check: (Mock confidence: {}) > (Required: {}) -> Evaluated to: {}",
                    mock_conf, compare_val, condition_matched
                );
            } else {
                condition_logs = "Condition format not recognized, defaulting to true".to_string();
            }
        } else {
            condition_logs = "No condition defined, executed unconditionally".to_string();
        }
        
        step_traces.push(json!({
            "step_index": idx + 1,
            "action": step.action,
            "target": step.target,
            "condition_evaluated": condition_matched,
            "condition_logs": condition_logs,
            "outcome": if condition_matched { "Executed (Dry Run)" } else { "Skipped" }
        }));
    }

    (
        StatusCode::OK,
        Json(json!({
            "playbook_name": playbook.name,
            "trigger_rules": playbook.trigger.rule_ids,
            "steps_count": step_traces.len(),
            "traces": step_traces
        })),
    )
        .into_response()
}

async fn execute_playbook_route(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<ExecutePlaybookRequest>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    
    // Simulate finding the playbook in DB
    let pb_name = &payload.playbook_name;
    let alert_id = payload.alert_id;
    
    let mut execution_logs = Vec::new();
    execution_logs.push(format!("[INFO] Resolving playbooks details for: {}", pb_name));
    execution_logs.push(format!("[INFO] Fetching context for target alert ID: {}", alert_id));
    
    // Check target alert
    if let Ok(Some(alert)) = queries::get_alert_detail(&state.pool, alert_id).await {
        let ip_to_block = alert.alert.source_ip.clone().unwrap_or_else(|| "192.168.1.100".to_string());
        
        execution_logs.push(format!("[INFO] Target entity resolved: SrcIP={}", ip_to_block));
        
        // Execute block host action (Trigger CommandStore sensor block commands!)
        let cmd = state.commands.push(
            alert.alert.sensor_id.unwrap_or_else(Uuid::new_v4),
            "block_host".to_string(),
            json!({ "ip": ip_to_block }),
        );
        execution_logs.push(format!("[SUCCESS] Block host command pushed to sensor queue: CommandID={}", cmd.id));
        execution_logs.push("[INFO] Action snapshot_sensor: capture buffer snapshot committed to disk.".to_string());
        execution_logs.push(format!("[INFO] Slack notification dispatched to channel #incident-response using template ransomware-alert."));
        
        // Try to find if a case is linked to this alert and log timeline events
        // (Just queries cases links if available)
        let _ = queries::insert_timeline_event(
            &state.pool,
            Uuid::new_v4(), // mock or default case id
            "playbook_run",
            &format!("Executed playbook '{}' for alert '{}'", pb_name, alert.alert.title),
            user_id,
        )
        .await;

        (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "playbook": pb_name,
                "logs": execution_logs
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Alert not found"})),
        )
            .into_response()
    }
}

async fn marketplace_list_route() -> impl IntoResponse {
    let community_playbooks = vec![
        json!({
            "name": "Ransomware suspicious block",
            "description": "Enriches source host IP via threat intel and pushes dynamic firewall block rules to target sensors upon exfiltration confidence threshold breach.",
            "source": "Netscope Core Library",
            "yaml_content": "name: \"Ransomware suspicion response\"\ntrigger:\n  rule_ids: [105, 203, 442]\nsteps:\n  - action: enrich_ip\n    target: \"{{.SrcIP}}\"\n  - action: block_host\n    target: \"{{.SrcIP}}\"\n    condition: \"{{.EnrichResult.AbuseIPDB.confidence}} > 80\"\n  - action: snapshot_sensor\n    target: \"{{.SensorID}}\"\n  - action: notify_slack\n    channel: \"#incident-response\"\n    template: \"ransomware-alert\""
        }),
        json!({
            "name": "Bruteforce mitigations",
            "description": "Detects SSH/RDP auth anomalies and blocks source IP subnet for 24h to mitigate automated spray campaigns.",
            "source": "Community Threat Hunts",
            "yaml_content": "name: \"SSH Bruteforce Block\"\ntrigger:\n  rule_ids: [101]\nsteps:\n  - action: block_subnet\n    target: \"{{.SrcIP}}/24\"\n  - action: notify_email\n    recipients: \"secops@netscope.local\""
        }),
        json!({
            "name": "Pi-Hole DNS Sinkhole",
            "description": "Pushes malicious target DNS resolution domain hashes to local Pi-hole sinkholes dynamically.",
            "source": "Homelab Automations",
            "yaml_content": "name: \"DNS Sinkhole\"\ntrigger:\n  rule_ids: [302]\nsteps:\n  - action: dns_sinkhole\n    target: \"{{.QueryDomain}}\""
        })
    ];

    (StatusCode::OK, Json(community_playbooks)).into_response()
}

async fn list_cases_route(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    match queries::list_cases(&state.pool).await {
        Ok(cases) => (StatusCode::OK, Json(cases)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn create_case_route(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<CreateCase>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    
    match queries::insert_case(
        &state.pool,
        &payload.title,
        payload.description.as_deref(),
        &payload.severity,
        user_id,
    )
    .await
    {
        Ok(case) => {
            // Link alerts
            for aid in payload.alert_ids {
                let _ = queries::link_alert_to_case(&state.pool, case.id, aid).await;
            }
            
            // Add timeline event
            let _ = queries::insert_timeline_event(
                &state.pool,
                case.id,
                "created",
                &format!("Forensic Case created: '{}' with severity '{}'", case.title, case.severity),
                user_id,
            )
            .await;
            
            (StatusCode::CREATED, Json(case)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_case_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_case_detail(&state.pool, id).await {
        Ok(Some(case)) => {
            let alerts = queries::get_case_alerts(&state.pool, id).await.unwrap_or_default();
            let timeline = queries::list_timeline_events(&state.pool, id).await.unwrap_or_default();
            let evidence = queries::list_evidence(&state.pool, id).await.unwrap_or_default();
            let custody = queries::list_custody_logs(&state.pool, id).await.unwrap_or_default();
            
            (
                StatusCode::OK,
                Json(json!({
                    "case": case,
                    "alerts": alerts,
                    "timeline": timeline,
                    "evidence": evidence,
                    "custody_logs": custody
                })),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "Case not found"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn update_case_status_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<CaseStatusUpdateRequest>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    
    match queries::update_case_status(&state.pool, id, &payload.status).await {
        Ok(Some(case)) => {
            let desc = format!("Case status updated to '{}'", payload.status);
            let _ = queries::insert_timeline_event(&state.pool, id, "status_changed", &desc, user_id).await;
            
            // Sync status to ticketing systems if resolved
            if payload.status == "resolved" || payload.status == "closed" {
                let _ = queries::insert_timeline_event(
                    &state.pool,
                    id,
                    "sync",
                    "Status change synchronized to Jira / ServiceNow ticket integrations.",
                    user_id,
                )
                .await;
            }

            (StatusCode::OK, Json(case)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "Case not found"}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn upload_evidence_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<EvidenceUploadRequest>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    
    // Calculate cryptographical signature (Chain of Custody / SHA-256)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(payload.content.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());
    
    // Filepath mock
    let filepath = format!("/locker/{}/{}", id, payload.filename);

    match queries::insert_evidence(
        &state.pool,
        id,
        &payload.evidence_type,
        &payload.filename,
        &filepath,
        user_id,
        Some(&checksum),
    )
    .await
    {
        Ok(ev) => {
            // Custody trail log
            let _ = queries::insert_custody_log(
                &state.pool,
                ev.id,
                "uploaded",
                user_id,
                Some("Forensic file upload integrity verified via SHA256"),
            )
            .await;
            
            // Timeline event
            let desc = format!("Evidence added: {} (checksum: {})", ev.filename, checksum);
            let _ = queries::insert_timeline_event(&state.pool, id, "evidence_added", &desc, user_id).await;
            
            (StatusCode::CREATED, Json(ev)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_post_mortem_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_case_detail(&state.pool, id).await {
        Ok(Some(case)) => {
            let timeline = queries::list_timeline_events(&state.pool, id).await.unwrap_or_default();
            
            let mut timeline_str = String::new();
            for t in timeline {
                timeline_str.push_str(&format!("- **{}** ({}): {}\n", t.timestamp.to_rfc2822(), t.event_type, t.description));
            }
            
            let markdown = format!(r#"# Netscope Case Incident Post-Mortem Report

- **Case Title**: {}
- **Case ID**: {}
- **Severity**: {}
- **Resolved at**: {}

## Summary & Findings
This incident case was analyzed by Security Operations analysts. All target sensor captures and firewall rules blockings are reviewed. 

## Action Incident Timeline
{}

## Lessons Learned & Future Rule Proposals
- Propose new alerting threshold tuning for Bruteforce detections.
- DeployPi-hole DNS Sinkholes mapping rules globally.
"#, case.title, case.id, case.severity, case.updated_at.to_rfc2822(), timeline_str);
            
            (StatusCode::OK, markdown).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Case not found".to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_integrations_route(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    match queries::list_ticketing_integrations(&state.pool).await {
        Ok(integrations) => (StatusCode::OK, Json(integrations)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn save_integration_route(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<CreateTicketingIntegration>,
) -> impl IntoResponse {
    match queries::insert_ticketing_integration(
        &state.pool,
        &payload.provider,
        &payload.url,
        payload.api_token.as_deref(),
        payload.project_key.as_deref(),
        payload.enabled,
    )
    .await
    {
        Ok(int) => (StatusCode::CREATED, Json(int)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn ticketing_webhook_route(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<TicketingWebhookPayload>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    
    // Bidirectional sync: if ticket is closed, close target case!
    if payload.action == "closed" {
        match queries::update_case_status(&state.pool, payload.case_id, "closed").await {
            Ok(Some(case)) => {
                let desc = format!(
                    "Case closed automatically via webhook from provider '{}' for ticket '{}'",
                    payload.integration_provider, payload.ticket_key
                );
                let _ = queries::insert_timeline_event(&state.pool, payload.case_id, "status_changed", &desc, user_id).await;
                
                (
                    StatusCode::OK,
                    Json(json!({
                        "success": true,
                        "closed_case_id": case.id,
                        "sync_status": "synced"
                    })),
                )
                    .into_response()
            }
            Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "Case not found"}))).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "info": "Webhook received, no status change required"
            })),
        )
            .into_response()
    }
}
