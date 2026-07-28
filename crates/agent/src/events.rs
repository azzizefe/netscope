use std::time::Instant;

use chrono::Utc;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::offline::OfflineEvent;
use crate::state::AgentState;

#[derive(Debug, Serialize)]
pub struct BatchEvent {
    pub sensor_id: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub raw_data: Option<String>,
    pub timestamp: String,
}

pub fn create_event_channel() -> (mpsc::Sender<RawEvent>, mpsc::Receiver<RawEvent>) {
    mpsc::channel(10_000)
}

pub struct RawEvent {
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub raw_data: Option<String>,
}

pub async fn event_loop(state: AgentState, mut rx: mpsc::Receiver<RawEvent>) {
    let batch_interval = std::time::Duration::from_millis(state.config.events.batch_interval_ms);
    let max_batch = state.config.events.batch_max_events;
    let use_compression = state.config.events.compression;

    let mut batch: Vec<BatchEvent> = Vec::with_capacity(max_batch);
    let mut last_flush = Instant::now();

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                let sensor_id = state.get_sensor_id()
                    .map(|id| id.to_string())
                    .unwrap_or_default();

                batch.push(BatchEvent {
                    sensor_id,
                    event_type: event.event_type,
                    severity: event.severity,
                    title: event.title,
                    description: event.description,
                    source_ip: event.source_ip,
                    dest_ip: event.dest_ip,
                    protocol: event.protocol,
                    port: event.port,
                    raw_data: event.raw_data,
                    timestamp: Utc::now().to_rfc3339(),
                });

                if batch.len() >= max_batch || last_flush.elapsed() >= batch_interval {
                    flush_batch(&state, &mut batch, use_compression).await;
                    last_flush = Instant::now();
                }
            }
            _ = tokio::time::sleep(batch_interval) => {
                if !batch.is_empty() && last_flush.elapsed() >= batch_interval {
                    flush_batch(&state, &mut batch, use_compression).await;
                    last_flush = Instant::now();
                }
            }
        }

        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            if !batch.is_empty() {
                flush_batch(&state, &mut batch, use_compression).await;
            }
            break;
        }
    }
}

async fn flush_batch(state: &AgentState, batch: &mut Vec<BatchEvent>, compress: bool) {
    if batch.is_empty() {
        return;
    }

    let json = serde_json::to_vec(batch).unwrap_or_default();

    if compress {
        let compressed = zstd_compress(&json);
        match state
            .http_post_raw("/api/v1/events/batch", compressed, "application/zstd")
            .await
        {
            Ok(_) => {
                tracing::debug!("Pushed {} compressed events", batch.len());
                batch.clear();
                return;
            }
            Err(e) => {
                tracing::warn!("Failed to push compressed events: {}", e);
            }
        }
    }

    match state
        .http_post_raw("/api/v1/events/batch", json, "application/json")
        .await
    {
        Ok(_) => {
            tracing::debug!("Pushed {} events", batch.len());
            batch.clear();
        }
        Err(e) => {
            tracing::warn!("Failed to push events: {}", e);
            offline_fallback(state, batch).await;
        }
    }
    batch.clear();
}

async fn offline_fallback(state: &AgentState, batch: &[BatchEvent]) {
    let offline = state.offline.lock().await;
    for event in batch {
        let oe = OfflineEvent {
            id: None,
            sensor_id: event.sensor_id.clone(),
            event_type: event.event_type.clone(),
            severity: event.severity.clone(),
            title: event.title.clone(),
            description: event.description.clone(),
            source_ip: event.source_ip.clone(),
            dest_ip: event.dest_ip.clone(),
            protocol: event.protocol.clone(),
            port: event.port,
            raw_data: event.raw_data.clone(),
            created_at: Utc::now().to_rfc3339(),
        };
        if let Err(e) = offline.push(&oe).await {
            tracing::error!("Offline buffer write failed: {}", e);
        }
    }
}

pub async fn flush_offline_buffer(state: &AgentState) {
    const BATCH_SIZE: usize = 500;

    loop {
        let batch = {
            let offline = state.offline.lock().await;
            offline.pop_batch(BATCH_SIZE).await.unwrap_or_default()
        };

        if batch.is_empty() {
            break;
        }

        let events: Vec<BatchEvent> = batch
            .iter()
            .map(|oe| BatchEvent {
                sensor_id: oe.sensor_id.clone(),
                event_type: oe.event_type.clone(),
                severity: oe.severity.clone(),
                title: oe.title.clone(),
                description: oe.description.clone(),
                source_ip: oe.source_ip.clone(),
                dest_ip: oe.dest_ip.clone(),
                protocol: oe.protocol.clone(),
                port: oe.port,
                raw_data: oe.raw_data.clone(),
                timestamp: oe.created_at.clone(),
            })
            .collect();

        let payload = serde_json::to_vec(&events).unwrap_or_default();
        match state
            .http_post_raw("/api/v1/events/batch", payload, "application/json")
            .await
        {
            Ok(_) => {
                let ids: Vec<i64> = batch.iter().filter_map(|e| e.id).collect();
                let offline = state.offline.lock().await;
                if let Err(e) = offline.delete_batch(&ids).await {
                    tracing::error!("Offline buffer cleanup failed: {}", e);
                }
                tracing::info!("Flushed {} offline events", ids.len());
            }
            Err(e) => {
                tracing::warn!("Offline flush failed (will retry): {}", e);
                break;
            }
        }
    }
}

fn zstd_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut compressed = Vec::new();
    let mut encoder = zstd::Encoder::new(&mut compressed, 3).unwrap();
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap();
    compressed
}
