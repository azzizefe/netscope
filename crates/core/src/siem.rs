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

    /// Format event as RFC 5424 Syslog line.
    /// Severity mapping: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Informational, 7=Debug.
    pub fn to_rfc5424(&self, severity: u8) -> String {
        let facility = 4; // security/authorization
        let pri = facility * 8 + (severity & 7);
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());
        
        let src_str = self.src.as_deref().unwrap_or("-");
        let dst_str = self.dst.as_deref().unwrap_or("-");
        let src_port_str = self.src_port.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        let dst_port_str = self.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        
        let sd = format!(
            "[netscope@42424 src_ip=\"{}\" dst_ip=\"{}\" src_port=\"{}\" dst_port=\"{}\" protocol=\"{}\" length=\"{}\"]",
            src_str, dst_str, src_port_str, dst_port_str, self.protocol, self.length
        );

        format!(
            "<{}>1 {} {} netscope-agent {} - - {} {}",
            pri, self.timestamp, hostname, std::process::id(), sd, self.summary
        )
    }

    /// Format event as CEF (Common Event Format)
    pub fn to_cef(&self, signature_id: &str, name: &str, severity: u8) -> String {
        let mut ext = Vec::new();
        if let Some(ref src) = self.src {
            ext.push(format!("src={}", src));
        }
        if let Some(ref dst) = self.dst {
            ext.push(format!("dst={}", dst));
        }
        if let Some(spt) = self.src_port {
            ext.push(format!("spt={}", spt));
        }
        if let Some(dpt) = self.dst_port {
            ext.push(format!("dpt={}", dpt));
        }
        ext.push(format!("proto={}", self.protocol));
        ext.push(format!("len={}", self.length));
        
        format!(
            "CEF:0|netscope|netscope-agent|2.0|{}|{}|{}|{}",
            signature_id, name, severity, ext.join(" ")
        )
    }

    /// Format event as LEEF (Log Event Extended Format)
    pub fn to_leef(&self, event_id: &str, severity: u8) -> String {
        let mut ext = Vec::new();
        ext.push(format!("devTime={}", self.timestamp));
        if let Some(ref src) = self.src {
            ext.push(format!("src={}", src));
        }
        if let Some(ref dst) = self.dst {
            ext.push(format!("dst={}", dst));
        }
        if let Some(spt) = self.src_port {
            ext.push(format!("srcPort={}", spt));
        }
        if let Some(dpt) = self.dst_port {
            ext.push(format!("dstPort={}", dpt));
        }
        ext.push(format!("proto={}", self.protocol));
        ext.push(format!("sev={}", severity));
        ext.push(format!("len={}", self.length));
        ext.push(format!("msg={}", self.summary));

        format!(
            "LEEF:1.0|netscope|netscope-agent|2.0|{}|{}",
            event_id,
            ext.join("\t")
        )
    }

    /// Format event as JSON Lines (NDJSON)
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Helper function to write a packet to a new pcapng file.
pub fn export_packet_to_pcapng(
    pkt: &Packet,
    path: &std::path::Path,
    comment: &str,
) -> std::io::Result<()> {
    use crate::pcapng::{InterfaceMeta, PcapngWriter, SectionMeta};
    let mut writer = PcapngWriter::create(
        path,
        SectionMeta {
            application: Some("netscope".to_string()),
            comment: Some("Auto-exported alert packet".to_string()),
            ..Default::default()
        },
        &[InterfaceMeta {
            linktype: 1, // Ethernet
            snaplen: 0,
            name: Some("netscope-nic".to_string()),
            description: Some("Netscope Captured Interface".to_string()),
        }],
    )?;

    let seconds = pkt.timestamp.timestamp();
    let nanos = pkt.timestamp.timestamp_subsec_nanos();

    writer.write_packet(
        0,
        seconds,
        nanos,
        pkt.length as u32,
        &pkt.data,
        Some(comment),
    )?;

    writer.finish()?;
    Ok(())
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
            let threat_engine = crate::threat::ThreatEngine::load();
            let mut batch = Vec::new();
            let batch_size = 50;
            let timeout = Duration::from_millis(500);
            let mut last_flush = std::time::Instant::now();

            while running.load(Ordering::SeqCst) || !rx.is_empty() {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(pkt) => {
                        // Check threat alerts for raw PCAP export
                        let alerts = threat_engine.check_packet(&pkt);
                        for alert in &alerts {
                            let alerts_dir = crate::config::config_dir()
                                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
                                .join("alerts");
                            if std::fs::create_dir_all(&alerts_dir).is_ok() {
                                let ts_safe = pkt
                                    .timestamp
                                    .format("%Y%m%dT%H%M%S%.6fZ")
                                    .to_string()
                                    .replace(":", "-");
                                let filename = format!("alert_{}_{}.pcapng", alert.sid, ts_safe);
                                let file_path = alerts_dir.join(filename);
                                let _ = export_packet_to_pcapng(&pkt, &file_path, &alert.msg);
                            }
                        }

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
            if let Ok(json) = event.to_ndjson() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use bytes::Bytes;
    use chrono::Utc;

    #[test]
    fn test_siem_event_formatting() {
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.10".parse().unwrap()),
            dst_addr: Some("8.8.8.8".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(53),
            protocol: Protocol::Dns,
            length: 85,
            summary: "DNS Query".to_string(),
            data: Bytes::from(vec![0; 85]),
            llm: None,
        };

        let event = SiemEvent::from_packet(&pkt);

        // 1. NDJSON test
        let ndjson = event.to_ndjson().unwrap();
        assert!(ndjson.contains("\"protocol\":\"DNS\""));
        assert!(ndjson.contains("\"length\":85"));

        // 2. Syslog RFC 5424 test
        let syslog = event.to_rfc5424(3); // Error severity
        assert!(syslog.contains("<35>1")); // facility 4 * 8 + severity 3 = 35
        assert!(syslog.contains("netscope-agent"));
        assert!(syslog.contains("src_ip=\"192.168.1.10\""));
        assert!(syslog.contains("dst_ip=\"8.8.8.8\""));

        // 3. CEF test
        let cef = event.to_cef("100002", "Suspicious Beaconing", 8);
        assert!(cef.starts_with("CEF:0|netscope|netscope-agent|2.0|100002|Suspicious Beaconing|8|"));
        assert!(cef.contains("src=192.168.1.10"));
        assert!(cef.contains("dst=8.8.8.8"));

        // 4. LEEF test
        let leef = event.to_leef("200001", 5);
        assert!(leef.starts_with("LEEF:1.0|netscope|netscope-agent|2.0|200001|"));
        assert!(leef.contains("src=192.168.1.10"));
        assert!(leef.contains("dst=8.8.8.8"));
        assert!(leef.contains("sev=5"));
    }

    #[test]
    fn test_raw_pcap_export() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_export.pcapng");
        
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("127.0.0.1".parse().unwrap()),
            dst_addr: Some("127.0.0.1".parse().unwrap()),
            src_port: Some(80),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 4,
            summary: "GET /".to_string(),
            data: Bytes::from(vec![1, 2, 3, 4]),
            llm: None,
        };

        let result = export_packet_to_pcapng(&pkt, &path, "Test export validation");
        assert!(result.is_ok());
        assert!(path.exists());

        // Cleanup
        let _ = std::fs::remove_file(path);
    }
}

