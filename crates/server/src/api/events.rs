use std::io::Read;
use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Query, State};
use axum::http::{StatusCode, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::db::models::{Event, EventFilter};
use crate::db::queries;

pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(list_events))
        .route("/batch", post(ingest_events_batch))
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
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
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let decompressed = if content_type == "application/zstd" {
        match decompress_zstd(&body) {
            Ok(data) => data,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("Decompress error: {}", e)}))),
        }
    } else {
        body.to_vec()
    };

    let events: Vec<BatchEvent> = match serde_json::from_slice(&decompressed) {
        Ok(events) => events,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("Invalid JSON: {}", e)})));
        }
    };

    if events.is_empty() {
        return (StatusCode::OK, Json(json!({"accepted": 0})));
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
            timestamp: Utc::now(),
        };

        match queries::insert_event(&state.pool, &db_event).await {
            Ok(_) => accepted += 1,
            Err(e) => tracing::warn!("Failed to insert event: {}", e),
        }
    }

    (StatusCode::OK, Json(json!({
        "accepted": accepted,
        "total": events.len(),
    })))
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = zstd::Decoder::new(data)?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}
