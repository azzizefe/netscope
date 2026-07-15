// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Packet;
use crossbeam_channel::Receiver;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct SiemEvent {
    pub timestamp: String,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: usize,
    pub summary: String,
}

impl SiemEvent {
    pub fn from_packet(pkt: &Packet) -> Self {
        SiemEvent {
            timestamp: pkt.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            src: pkt.src_addr.map(|a| a.to_string()),
            dst: pkt.dst_addr.map(|a| a.to_string()),
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol.to_string(),
            length: pkt.length,
            summary: pkt.summary.clone(),
        }
    }
}

pub struct SiemExporter {
    running: Arc<AtomicBool>,
    es_url: Option<String>,
    splunk_url: Option<String>,
    splunk_token: Option<String>,
}

impl SiemExporter {
    pub fn new(
        es_url: Option<String>,
        splunk_url: Option<String>,
        splunk_token: Option<String>,
    ) -> Self {
        SiemExporter {
            running: Arc::new(AtomicBool::new(false)),
            es_url,
            splunk_url,
            splunk_token,
        }
    }

    pub fn start(&self, rx: Receiver<Packet>) -> thread::JoinHandle<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);
        let es_url = self.es_url.clone();
        let splunk_url = self.splunk_url.clone();
        let splunk_token = self.splunk_token.clone();

        thread::spawn(move || {
            let mut batch = Vec::new();
            let batch_size = 50;
            let timeout = Duration::from_millis(500);
            let mut last_flush = std::time::Instant::now();

            while running.load(Ordering::SeqCst) || !rx.is_empty() {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(pkt) => {
                        batch.push(SiemEvent::from_packet(&pkt));
                        if batch.len() >= batch_size || last_flush.elapsed() >= timeout {
                            flush_batch(
                                &batch,
                                es_url.as_deref(),
                                splunk_url.as_deref(),
                                splunk_token.as_deref(),
                            );
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            flush_batch(
                                &batch,
                                es_url.as_deref(),
                                splunk_url.as_deref(),
                                splunk_token.as_deref(),
                            );
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            flush_batch(
                                &batch,
                                es_url.as_deref(),
                                splunk_url.as_deref(),
                                splunk_token.as_deref(),
                            );
                            batch.clear();
                        }
                        break;
                    }
                }
            }
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

fn flush_batch(
    batch: &[SiemEvent],
    es_url: Option<&str>,
    splunk_url: Option<&str>,
    splunk_token: Option<&str>,
) {
    if batch.is_empty() {
        return;
    }

    if let Some(url) = es_url {
        let mut bulk_body = String::new();
        for event in batch {
            bulk_body.push_str("{\"index\":{\"_index\":\"netscope-packets\"}}\n");
            if let Ok(json) = serde_json::to_string(event) {
                bulk_body.push_str(&json);
                bulk_body.push('\n');
            }
        }

        let agent = ureq::Agent::new();
        let res = agent
            .post(url)
            .set("Content-Type", "application/x-ndjson")
            .send_string(&bulk_body);
        if let Err(e) = res {
            eprintln!("SIEM Elasticsearch export error: {}", e);
        }
    }

    if let (Some(url), Some(token)) = (splunk_url, splunk_token) {
        let mut splunk_body = String::new();
        for event in batch {
            let mut event_wrapper = serde_json::Map::new();
            event_wrapper.insert(
                "event".to_string(),
                serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
            );
            if let Ok(json) = serde_json::to_string(&event_wrapper) {
                splunk_body.push_str(&json);
                splunk_body.push('\n');
            }
        }

        let agent = ureq::Agent::new();
        let res = agent
            .post(url)
            .set("Authorization", &format!("Splunk {}", token))
            .set("Content-Type", "application/json")
            .send_string(&splunk_body);
        if let Err(e) = res {
            eprintln!("SIEM Splunk HEC export error: {}", e);
        }
    }
}
