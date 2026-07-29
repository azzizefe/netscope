use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{require, Claims};
use crate::db::models::{CreateSavedSearch, HistogramPayload, HuntQueryPayload, HuntRule};
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    let read = || from_fn(require("events:read"));
    let write = || from_fn(require("events:write"));

    Router::new()
        .route("/events", post(hunt_events_route).route_layer(read()))
        .route("/histogram", post(hunt_histogram_route).route_layer(read()))
        .route(
            "/saved-searches",
            get(list_saved_searches_route)
                .route_layer(read())
                .post(create_saved_search_route)
                .route_layer(write()),
        )
        .route(
            "/saved-searches/{id}/convert-to-rule",
            post(convert_to_rule_route).route_layer(write()),
        )
        .with_state(state)
}

async fn hunt_events_route(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<HuntQueryPayload>,
) -> impl IntoResponse {
    match queries::hunt_events(&state.pool, &payload).await {
        Ok(events) => {
            // Threat Intel Overlay: Add VT and AbuseIPDB mock intelligence metadata
            let mut overlay = serde_json::Map::new();
            for ev in &events {
                if let Some(ref ip) = ev.source_ip {
                    if !ip.starts_with("192.168")
                        && !ip.starts_with("10.")
                        && !overlay.contains_key(ip)
                    {
                        overlay.insert(
                            ip.clone(),
                            json!({
                                "provider": "AbuseIPDB",
                                "score": 85,
                                "verdict": "Known Scanner / Attack Indicator",
                                "class": "badge-high"
                            }),
                        );
                    }
                }
                if let Some(ref ip) = ev.dest_ip {
                    if !ip.starts_with("192.168")
                        && !ip.starts_with("10.")
                        && !overlay.contains_key(ip)
                    {
                        overlay.insert(
                            ip.clone(),
                            json!({
                                "provider": "VirusTotal",
                                "score": 92,
                                "verdict": "Malicious Command & Control Node",
                                "class": "badge-critical"
                            }),
                        );
                    }
                }
            }

            (
                StatusCode::OK,
                Json(json!({
                    "events": events,
                    "threat_intel_overlay": overlay
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

async fn hunt_histogram_route(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<HistogramPayload>,
) -> impl IntoResponse {
    match queries::hunt_histogram(&state.pool, &payload).await {
        Ok(buckets) => (StatusCode::OK, Json(buckets)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_saved_searches_route(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    match queries::list_saved_searches(&state.pool).await {
        Ok(searches) => (StatusCode::OK, Json(searches)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn create_saved_search_route(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(payload): Json<CreateSavedSearch>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    match queries::insert_saved_search(&state.pool, &payload.name, &payload.query_json, user_id)
        .await
    {
        Ok(search) => (StatusCode::CREATED, Json(search)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn convert_to_rule_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    claims: Option<axum::extract::Extension<Claims>>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);

    // 1. Fetch saved search
    match queries::get_saved_search(&state.pool, id).await {
        Ok(Some(search)) => {
            // 2. Parse query_json into HuntRule
            let rule_tree: Result<HuntRule, _> = serde_json::from_value(search.query_json.clone());
            let mut cond_map = serde_json::Map::new();

            if let Ok(ref tree) = rule_tree {
                flatten_hunt_rule(tree, &mut cond_map);
            }

            // Default rule details
            let rule_name = format!("Converted Hunt Rule: {}", search.name);
            let description = format!(
                "Alert generated from saved Threat Hunt Query: {}",
                search.name
            );
            let condition_val = serde_json::Value::Object(cond_map);

            let create_payload = crate::db::models::CreateRule {
                name: rule_name,
                description: Some(description),
                enabled: Some(true),
                severity: Some("medium".to_string()),
                condition: condition_val,
                actions: Some(json!([])),
                cooldown_secs: Some(300),
            };

            // 3. Create the alert rule
            match queries::create_rule(&state.pool, &create_payload, user_id).await {
                Ok(rule) => (StatusCode::CREATED, Json(rule)).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to create alert rule: {}", e)})),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Saved search not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn flatten_hunt_rule(rule: &HuntRule, cond_map: &mut serde_json::Map<String, serde_json::Value>) {
    match rule {
        HuntRule::Group { logical, rules } => {
            if logical.to_uppercase() == "AND" {
                for r in rules {
                    flatten_hunt_rule(r, cond_map);
                }
            }
        }
        HuntRule::Condition {
            field,
            operator,
            value,
        } => {
            if operator == "equals" || operator == "eq" {
                cond_map.insert(field.clone(), value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hunt_rule_to_sql_compiler() {
        let condition1 = HuntRule::Condition {
            field: "protocol".to_string(),
            operator: "eq".to_string(),
            value: json!("TCP"),
        };
        let condition2 = HuntRule::Condition {
            field: "port".to_string(),
            operator: "gt".to_string(),
            value: json!(80),
        };

        let root = HuntRule::Group {
            logical: "AND".to_string(),
            rules: vec![condition1, condition2],
        };

        let mut idx = 1u32;
        let mut params = Vec::new();
        let sql = root.to_sql(&mut idx, &mut params).unwrap();

        assert_eq!(sql, "(((protocol = $1) AND (port::text > $2)))");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "TCP");
        assert_eq!(params[1], "80");
    }

    #[test]
    fn test_flatten_hunt_rule_for_alert_conversion() {
        let condition1 = HuntRule::Condition {
            field: "severity".to_string(),
            operator: "equals".to_string(),
            value: json!("critical"),
        };
        let condition2 = HuntRule::Condition {
            field: "protocol".to_string(),
            operator: "eq".to_string(),
            value: json!("UDP"),
        };

        let root = HuntRule::Group {
            logical: "AND".to_string(),
            rules: vec![condition1, condition2],
        };

        let mut cond_map = serde_json::Map::new();
        flatten_hunt_rule(&root, &mut cond_map);

        assert_eq!(
            cond_map.get("severity").unwrap().as_str().unwrap(),
            "critical"
        );
        assert_eq!(cond_map.get("protocol").unwrap().as_str().unwrap(), "UDP");
    }
}
