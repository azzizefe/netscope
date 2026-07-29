use std::io::Read;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::require;
use crate::db::models::{Event, EventFilter};
use crate::db::queries;
use crate::ws::WsState;

/// Reading the event store and writing to it are separate privileges.
///
/// `/batch` is how a sensor injects events into the SOC timeline. Gating it at
/// `events:read` — which every role holds — meant any valid token could
/// fabricate security events.
pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(
            "/",
            get(list_events).route_layer(from_fn(require("events:read"))),
        )
        .route(
            "/batch",
            post(ingest_events_batch).route_layer(from_fn(require("events:write"))),
        )
        .with_state(state)
}

async fn list_events(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<EventQueryParams>,
) -> impl IntoResponse {
    let filter = EventFilter {
        severity: params.severity,
        sensor_id: params.sensor_id,
        timerange_start: params.timerange_start,
        timerange_end: params.timerange_end,
        event_type: params.event_type,
        page: params.page,
        per_page: params.per_page,
    };

    match queries::list_events(&state.pool, &filter).await {
        Ok(events) => (StatusCode::OK, Json(json!(events))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct EventQueryParams {
    severity: Option<String>,
    sensor_id: Option<Uuid>,
    timerange_start: Option<chrono::DateTime<chrono::Utc>>,
    timerange_end: Option<chrono::DateTime<chrono::Utc>>,
    event_type: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Debug, serde::Deserialize)]
struct BatchEvent {
    sensor_id: String,
    event_type: String,
    severity: String,
    title: String,
    description: Option<String>,
    source_ip: Option<String>,
    dest_ip: Option<String>,
    protocol: Option<String>,
    port: Option<i32>,
    raw_data: Option<String>,
    timestamp: String,
}

async fn ingest_events_batch(
    State(state): State<Arc<ApiState>>,
    axum::extract::Extension(ws): axum::extract::Extension<Arc<WsState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    if let Some(ref cache) = state.cache {
        let rate_key = format!("rate_limit:events:{}", client_ip);
        if is_rate_limited(cache, &rate_key, 60, 60).await {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Rate limit exceeded (max 60 batch requests per minute)"})),
            )
                .into_response();
        }
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let decompressed = if content_type == "application/zstd" {
        match decompress_zstd(&body) {
            Ok(data) => data,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Decompress error: {}", e)})),
                )
                    .into_response()
            }
        }
    } else {
        body.to_vec()
    };

    let events: Vec<BatchEvent> = match serde_json::from_slice(&decompressed) {
        Ok(events) => events,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid JSON: {}", e)})),
            )
                .into_response();
        }
    };

    if events.is_empty() {
        return (StatusCode::OK, Json(json!({"accepted": 0}))).into_response();
    }

    let mut accepted = 0u64;
    for ev in &events {
        let sensor_id = Uuid::parse_str(&ev.sensor_id).ok();
        let db_event = Event {
            id: Uuid::new_v4(),
            sensor_id,
            event_type: ev.event_type.clone(),
            severity: ev.severity.clone(),
            title: ev.title.clone(),
            description: ev.description.clone(),
            source_ip: ev.source_ip.clone(),
            dest_ip: ev.dest_ip.clone(),
            protocol: ev.protocol.clone(),
            port: ev.port,
            raw_data: ev.raw_data.as_ref().map(|s| json!(s)),
            tags: json!([]),
            timestamp: DateTime::parse_from_rfc3339(&ev.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        };

        match queries::insert_event(&state.pool, &db_event).await {
            Ok(inserted_ev) => {
                accepted += 1;
                ws.broadcast(&inserted_ev);

                if let Ok(rules) = queries::list_rules(&state.pool).await {
                    for rule in rules {
                        if rule.enabled && event_matches_rule(&inserted_ev, &rule) {
                            evaluate_alert_dedup(
                                &state.pool,
                                state.cache.as_deref(),
                                &inserted_ev,
                                &rule,
                            )
                            .await;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("Failed to insert event: {}", e),
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "accepted": accepted,
            "total": events.len(),
        })),
    )
        .into_response()
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = zstd::Decoder::new(data)?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

pub async fn is_rate_limited(
    cache: &crate::cache::CacheLayer,
    key: &str,
    limit: u64,
    window_secs: u64,
) -> bool {
    match cache.incr(key).await {
        Ok(count) => {
            if count == 1 {
                if let Err(e) = cache.expire(key, window_secs as i64).await {
                    tracing::error!("Failed to set TTL for rate limit key {}: {}", key, e);
                }
            }
            count as u64 > limit
        }
        Err(e) => {
            tracing::error!("Redis rate limit incr error for key {}: {}", key, e);
            false
        }
    }
}

pub fn event_matches_rule(event: &Event, rule: &crate::db::models::AlertRule) -> bool {
    let cond = &rule.condition;
    if let Some(et) = cond.get("event_type").and_then(|v| v.as_str()) {
        if et != event.event_type {
            return false;
        }
    }
    if let Some(sev) = cond.get("severity").and_then(|v| v.as_str()) {
        if sev != event.severity {
            return false;
        }
    }
    if let Some(proto) = cond.get("protocol").and_then(|v| v.as_str()) {
        if event.protocol.as_deref() != Some(proto) {
            return false;
        }
    }
    if let Some(port) = cond.get("port").and_then(|v| v.as_i64()) {
        if event.port.map(|p| p as i64) != Some(port) {
            return false;
        }
    }
    true
}

pub async fn evaluate_alert_dedup(
    pool: &sqlx::PgPool,
    cache: Option<&crate::cache::CacheLayer>,
    event: &Event,
    rule: &crate::db::models::AlertRule,
) {
    if let Some(cache_layer) = cache {
        let dedup_key = format!(
            "alert:dedup:{}:{}",
            rule.id,
            event.sensor_id.unwrap_or_default()
        );
        match cache_layer
            .set_nx_ttl(&dedup_key, "1", rule.cooldown_secs as u64)
            .await
        {
            Ok(true) => {
                create_alert_and_log(pool, event, rule).await;
            }
            Ok(false) => {
                tracing::debug!(
                    "Deduplicated alert for rule {} sensor {:?}",
                    rule.id,
                    event.sensor_id
                );
            }
            Err(e) => {
                tracing::error!("Redis alert dedup check failed: {}", e);
                create_alert_and_log(pool, event, rule).await;
            }
        }
    } else {
        create_alert_and_log(pool, event, rule).await;
    }
}

async fn create_alert_and_log(
    pool: &sqlx::PgPool,
    event: &Event,
    rule: &crate::db::models::AlertRule,
) {
    let title = format!("Alert triggered: {}", rule.name);
    match queries::insert_alert(
        pool,
        queries::NewAlert {
            rule_id: Some(rule.id),
            sensor_id: event.sensor_id,
            event_id: Some(event.id),
            severity: &rule.severity,
            title: &title,
            description: rule.description.as_deref(),
            source_ip: event.source_ip.as_deref(),
            dest_ip: event.dest_ip.as_deref(),
            raw_data: event.raw_data.as_ref(),
        },
    )
    .await
    {
        Ok(alert) => {
            tracing::info!("Alert created for rule {} (ID: {})", rule.name, alert.id);
        }
        Err(e) => {
            tracing::error!("Failed to create alert: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::AlertRule;
    use serde_json::json;

    #[test]
    fn test_event_matches_rule_basic() {
        let event = Event {
            id: Uuid::new_v4(),
            sensor_id: Some(Uuid::new_v4()),
            event_type: "threat".into(),
            severity: "high".into(),
            title: "SQL Injection".into(),
            description: None,
            source_ip: Some("192.168.1.1".into()),
            dest_ip: Some("10.0.0.1".into()),
            protocol: Some("tcp".into()),
            port: Some(80),
            raw_data: None,
            tags: json!([]),
            timestamp: chrono::Utc::now(),
        };

        let rule1 = AlertRule {
            id: Uuid::new_v4(),
            name: "Test Rule 1".into(),
            description: None,
            enabled: true,
            severity: "high".into(),
            condition: json!({
                "event_type": "threat",
                "severity": "high"
            }),
            actions: json!([]),
            cooldown_secs: 60,
            created_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(event_matches_rule(&event, &rule1));

        let rule2 = AlertRule {
            condition: json!({
                "protocol": "tcp",
                "port": 80
            }),
            ..rule1.clone()
        };
        assert!(event_matches_rule(&event, &rule2));

        let rule3 = AlertRule {
            condition: json!({
                "event_type": "anomaly"
            }),
            ..rule1.clone()
        };
        assert!(!event_matches_rule(&event, &rule3));
    }

    #[tokio::test]
    async fn test_redis_operations_if_available() {
        let redis_url = "redis://127.0.0.1:6379";
        let cache_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            crate::cache::CacheLayer::new(redis_url),
        )
        .await;

        let cache = match cache_result {
            Ok(Ok(c)) => c,
            _ => {
                println!("Skipping Redis cache tests because no local Redis server was found or connection timed out.");
                return;
            }
        };

        let test_key_limit = format!("test:rate_limit:{}", Uuid::new_v4());

        let limited1 = is_rate_limited(&cache, &test_key_limit, 2, 10).await;
        assert!(!limited1);

        let limited2 = is_rate_limited(&cache, &test_key_limit, 2, 10).await;
        assert!(!limited2);

        let limited3 = is_rate_limited(&cache, &test_key_limit, 2, 10).await;
        assert!(limited3);

        let test_key_nx = format!("test:nx:{}", Uuid::new_v4());
        let set1 = cache.set_nx_ttl(&test_key_nx, "val", 10).await.unwrap();
        assert!(set1);

        let set2 = cache.set_nx_ttl(&test_key_nx, "val2", 10).await.unwrap();
        assert!(!set2);
    }
}
