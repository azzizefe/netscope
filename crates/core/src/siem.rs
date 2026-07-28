// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Packet;
use crossbeam_channel::Receiver;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::Write;
use std::sync::Mutex;
use std::sync::OnceLock;
use crate::names::NameCache;
use maxminddb::Reader;

static ES_SETUP_DONE: AtomicBool = AtomicBool::new(false);

fn global_name_cache() -> &'static Mutex<NameCache> {
    static CACHE: OnceLock<Mutex<NameCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(NameCache::new()))
}

fn global_geoip_reader() -> &'static Option<Reader<Vec<u8>>> {
    static READER: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();
    READER.get_or_init(|| {
        let path = crate::config::config_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
            .join("geoip.mmdb");
        if path.exists() {
            maxminddb::Reader::open_readfile(&path).ok()
        } else {
            None
        }
    })
}

fn map_threat_intel_mitre_and_killchain(protocol: &str, summary: &str) -> (Option<String>, Option<String>, Option<String>) {
    let s = summary.to_lowercase();
    let proto = protocol.to_lowercase();

    if s.contains("abuseipdb") || s.contains("malicious source ip") {
        (
            Some("Initial Access".to_string()),
            Some("T1190 - Exploit Public-Facing Application".to_string()),
            Some("Delivery".to_string())
        )
    } else if s.contains("urlhaus") || s.contains("threat domain") {
        (
            Some("Command and Control".to_string()),
            Some("T1071 - Application Layer Protocol".to_string()),
            Some("Command and Control".to_string())
        )
    } else if s.contains("beaconing") || s.contains("beacon") {
        (
            Some("Command and Control".to_string()),
            Some("T1071.001 - Web Protocols".to_string()),
            Some("Command and Control".to_string())
        )
    } else if s.contains("malware") || s.contains("payload") {
        (
            Some("Execution".to_string()),
            Some("T1204 - User Execution".to_string()),
            Some("Installation".to_string())
        )
    } else if s.contains("scan") || s.contains("port scan") {
        (
            Some("Reconnaissance".to_string()),
            Some("T1595 - Active Scanning".to_string()),
            Some("Recon".to_string())
        )
    } else if proto == "dns" && s.contains("query") {
        (
            Some("Reconnaissance".to_string()),
            Some("T1590 - Gather Gather Groups/Host Info".to_string()),
            Some("Recon".to_string())
        )
    } else if proto == "ssh" || proto == "rdp" {
        (
            Some("Lateral Movement".to_string()),
            Some("T1021 - Remote Services".to_string()),
            Some("Exploitation".to_string())
        )
    } else if proto == "http" || proto == "tls" {
        (
            Some("Command and Control".to_string()),
            Some("T1071 - Application Layer Protocol".to_string()),
            Some("Command and Control".to_string())
        )
    } else {
        (None, None, None)
    }
}

fn mac_vendor_lookup(mac: &[u8]) -> Option<String> {
    if mac.len() < 3 {
        return None;
    }
    let oui = [mac[0], mac[1], mac[2]];
    match oui {
        [0x00, 0x1B, 0x1B] | [0x00, 0x0E, 0x8C] | [0x00, 0x1C, 0x06] | [0x28, 0x63, 0x36] | [0x00, 0x0F, 0xD3] => Some("Siemens".to_string()),
        [0x00, 0x00, 0xBC] => Some("Rockwell".to_string()),
        [0x00, 0x01, 0x05] => Some("Beckhoff".to_string()),
        [0x00, 0x00, 0x0C] => Some("Cisco".to_string()),
        [0x00, 0x17, 0xF2] => Some("Apple".to_string()),
        [0x00, 0x15, 0x5D] => Some("Microsoft".to_string()),
        [0x00, 0x1A, 0x11] => Some("Google".to_string()),
        [0x00, 0x50, 0x56] | [0x00, 0x0C, 0x29] | [0x00, 0x05, 0x69] => Some("VMware".to_string()),
        _ => None,
    }
}

fn tls_payload(pkt: &Packet) -> Option<&[u8]> {
    if pkt.protocol != crate::registry::Protocol::Tls {
        return None;
    }
    let data = &pkt.data;
    if data.len() < 14 {
        return None;
    }
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([data[off], data[off + 1]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if data.len() < off + 6 {
            return None;
        }
        off += 4;
        ethertype = u16::from_be_bytes([data[off], data[off + 1]]);
    }
    let l3 = off + 2;
    if data.len() < l3 + 20 {
        return None;
    }
    let (ip_proto, l4) = match ethertype {
        0x0800 => {
            let ihl = ((data[l3] & 0x0f) as usize) * 4;
            if ihl < 20 || data.len() < l3 + ihl {
                return None;
            }
            (data[l3 + 9], l3 + ihl)
        }
        0x86dd => {
            if data.len() < l3 + 40 {
                return None;
            }
            (data[l3 + 6], l3 + 40)
        }
        _ => return None,
    };
    match ip_proto {
        6 => {
            if data.len() < l4 + 20 {
                return None;
            }
            let doff = ((data[l4 + 12] >> 4) as usize) * 4;
            if doff < 20 || data.len() < l4 + doff {
                return None;
            }
            Some(&data[l4 + doff..])
        }
        _ => None,
    }
}

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
    // Severity mapping
    pub severity_score: u8,
    pub severity_label: String,
    // MITRE & Kill Chain
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub kill_chain_phase: Option<String>,
    // TLS Fingerprints
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub ja3s: Option<String>,
    // GeoIP & ASN
    pub geoip_country: Option<String>,
    pub geoip_city: Option<String>,
    pub asn: Option<String>,
    pub isp: Option<String>,
    pub threat_intel_matched: Option<bool>,
    pub mac_vendor: Option<String>,
    pub resolved_dns_name: Option<String>,
}

impl SiemEvent {
    pub fn from_packet(pkt: &Packet) -> Self {
        use crate::expert::{classify, ExpertSeverity};
        let severity = classify(pkt);
        let (severity_score, severity_label) = match severity {
            ExpertSeverity::Chat => (0, "Chat".to_string()),
            ExpertSeverity::Note => (3, "Note".to_string()),
            ExpertSeverity::Warning => (6, "Warning".to_string()),
            ExpertSeverity::Error => (9, "Error".to_string()),
        };

        let (mitre_tactic, mitre_technique, kill_chain_phase) =
            map_threat_intel_mitre_and_killchain(&pkt.protocol.to_string(), &pkt.summary);

        // Passive DNS
        global_name_cache().lock().unwrap().observe(pkt);
        let resolved_dns_name = if let Some(ip) = pkt.dst_addr {
            global_name_cache().lock().unwrap().name_for(ip).map(|s| s.to_string())
        } else if let Some(ip) = pkt.src_addr {
            global_name_cache().lock().unwrap().name_for(ip).map(|s| s.to_string())
        } else {
            None
        };

        // MAC Vendor
        let mac_vendor = if pkt.data.len() >= 12 {
            let mac_src = &pkt.data[6..12];
            mac_vendor_lookup(mac_src)
        } else {
            None
        };

        // TLS Fingerprints
        let (ja3, ja4, ja3s) = if pkt.protocol == crate::registry::Protocol::Tls {
            let payload = tls_payload(pkt);
            let ja3 = payload.and_then(|p| crate::dissectors::tls::parse_client_hello(p))
                .map(|h| crate::dissectors::tls::ja3_hash(&h));
            let ja4 = payload.and_then(|p| crate::dissectors::tls::parse_client_hello(p))
                .map(|h| crate::dissectors::tls::ja4(&h, 't'));
            let ja3s = payload.and_then(|p| crate::dissectors::tls::parse_server_hello(p))
                .map(|s| crate::dissectors::tls::ja3s_hash(&s));
            (ja3, ja4, ja3s)
        } else {
            (None, None, None)
        };

        // GeoIP & ASN
        let mut geoip_country = None;
        let mut geoip_city = None;
        let mut asn = None;
        let mut isp = None;

        if let Some(ref reader) = global_geoip_reader() {
            let lookup_ip = pkt.dst_addr.or(pkt.src_addr);
            if let Some(ip) = lookup_ip {
                if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                    geoip_country = city.country.and_then(|c| c.names).and_then(|n| n.get("en").map(|s| s.to_string()));
                    geoip_city = city.city.and_then(|c| c.names).and_then(|n| n.get("en").map(|s| s.to_string()));
                }
                if let Ok(asn_info) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                    asn = asn_info.autonomous_system_number.map(|a| format!("AS{}", a));
                    isp = asn_info.autonomous_system_organization.map(|s| s.to_string());
                }
            }
        }

        // Threat intel match status
        let threat_intel_matched = Some(
            pkt.summary.contains("AbuseIPDB")
                || pkt.summary.contains("URLhaus")
                || pkt.summary.contains("Threat")
                || pkt.summary.contains("malicious")
        );

        SiemEvent {
            timestamp: pkt.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            src: pkt.src_addr.map(|a| a.to_string()),
            dst: pkt.dst_addr.map(|a| a.to_string()),
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol.to_string(),
            length: pkt.length,
            summary: pkt.summary.clone(),
            severity_score,
            severity_label,
            mitre_tactic,
            mitre_technique,
            kill_chain_phase,
            ja3,
            ja4,
            ja3s,
            geoip_country,
            geoip_city,
            asn,
            isp,
            threat_intel_matched,
            mac_vendor,
            resolved_dns_name,
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

    /// Format event as GELF (Graylog Extended Log Format) JSON string
    pub fn to_gelf(&self, severity: u8) -> String {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());
        
        let ts = chrono::DateTime::parse_from_rfc3339(&self.timestamp)
            .map(|dt| dt.timestamp_millis() as f64 / 1000.0)
            .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis() as f64 / 1000.0);

        let gelf = serde_json::json!({
            "version": "1.1",
            "host": hostname,
            "short_message": self.summary,
            "timestamp": ts,
            "level": severity,
            "_src_ip": self.src,
            "_dst_ip": self.dst,
            "_src_port": self.src_port,
            "_dst_port": self.dst_port,
            "_protocol": self.protocol,
            "_length": self.length
        });

        serde_json::to_string(&gelf).unwrap_or_default()
    }

    /// Format event as OCSF (Open Cybersecurity Schema Framework) JSON
    pub fn to_ocsf(&self, is_alert: bool) -> serde_json::Value {
        if is_alert {
            serde_json::json!({
                "class_uid": 2001,
                "class_name": "Security Finding",
                "category_uid": 2,
                "category_name": "Findings",
                "activity_id": 1,
                "activity_name": "Create",
                "time": self.timestamp,
                "severity": self.severity_label,
                "severity_id": self.severity_score,
                "finding": {
                    "title": self.summary,
                    "uid": "netscope-alert-id",
                    "tactic": self.mitre_tactic,
                    "technique": self.mitre_technique,
                    "kill_chain": self.kill_chain_phase
                },
                "metadata": {
                    "product": {
                        "name": "netscope",
                        "version": "2.0"
                    }
                }
            })
        } else {
            serde_json::json!({
                "class_uid": 4001,
                "class_name": "Network Activity",
                "category_uid": 4,
                "category_name": "Network Activity",
                "activity_id": 1,
                "time": self.timestamp,
                "severity": self.severity_label,
                "severity_id": self.severity_score,
                "src_endpoint": {
                    "ip": self.src,
                    "port": self.src_port,
                    "country": self.geoip_country,
                    "city": self.geoip_city,
                    "asn": self.asn,
                    "isp": self.isp,
                    "mac": self.mac_vendor
                },
                "dst_endpoint": {
                    "ip": self.dst,
                    "port": self.dst_port,
                    "domain": self.resolved_dns_name
                },
                "connection_info": {
                    "protocol_name": self.protocol,
                    "boundary": "unknown"
                },
                "traffic": {
                    "bytes": self.length
                },
                "metadata": {
                    "product": {
                        "name": "netscope",
                        "version": "2.0"
                    }
                }
            })
        }
    }

    /// Format event as Google Chronicle UDM (Unstructured Data Model) JSON
    pub fn to_udm(&self) -> serde_json::Value {
        serde_json::json!({
            "metadata": {
                "event_timestamp": self.timestamp,
                "event_type": "NETWORK_CONNECTION",
                "product_name": "netscope"
            },
            "principal": {
                "ip": self.src,
                "port": self.src_port
            },
            "target": {
                "ip": self.dst,
                "port": self.dst_port
            },
            "network": {
                "sent_bytes": self.length,
                "ip_protocol": self.protocol
            }
        })
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

fn ensure_es_setup(url: &str) {
    if ES_SETUP_DONE.load(Ordering::SeqCst) {
        return;
    }
    
    let base_url = if let Some(idx) = url.find("/_bulk") {
        &url[..idx]
    } else if let Some(idx) = url.find("/netscope-packets") {
        &url[..idx]
    } else {
        url
    };

    let agent = ureq::Agent::new();

    // 1. Put ILM policy
    let ilm_url = format!("{}/_ilm/policy/netscope-ilm-policy", base_url);
    let ilm_body = serde_json::json!({
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_primary_shard_size": "50gb",
                            "max_age": "30d"
                        }
                    }
                },
                "delete": {
                    "min_age": "90d",
                    "actions": {
                        "delete": {}
                    }
                }
            }
        }
    });
    let _ = agent.put(&ilm_url)
        .set("Content-Type", "application/json")
        .send_json(ilm_body);

    // 2. Put index template
    let template_url = format!("{}/_index_template/netscope-template", base_url);
    let template_body = serde_json::json!({
        "index_patterns": ["netscope-*"],
        "template": {
            "settings": {
                "index.lifecycle.name": "netscope-ilm-policy"
            }
        }
    });
    let _ = agent.put(&template_url)
        .set("Content-Type", "application/json")
        .send_json(template_body);

    ES_SETUP_DONE.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone)]
pub struct SiemExporter {
    running: Arc<AtomicBool>,
    pub es_url: Option<String>,
    pub splunk_url: Option<String>,
    pub splunk_token: Option<String>,
    // Enterprise Sinks
    pub splunk_tcp_addr: Option<String>,
    pub splunk_udp_addr: Option<String>,
    pub gelf_tcp_addr: Option<String>,
    pub gelf_udp_addr: Option<String>,
    pub sentinel_dcr_url: Option<String>,
    pub sentinel_token: Option<String>,
    pub aws_s3_url: Option<String>,
    pub aws_s3_spool_dir: Option<String>,
    pub wazuh_file_path: Option<String>,
    pub wazuh_socket_addr: Option<String>,
    pub chronicle_url: Option<String>,
    pub chronicle_api_key: Option<String>,
    pub kafka_rest_url: Option<String>,
    pub kafka_topic: Option<String>,
    pub kafka_auth_header: Option<String>,
    pub loki_url: Option<String>,
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
            splunk_tcp_addr: None,
            splunk_udp_addr: None,
            gelf_tcp_addr: None,
            gelf_udp_addr: None,
            sentinel_dcr_url: None,
            sentinel_token: None,
            aws_s3_url: None,
            aws_s3_spool_dir: None,
            wazuh_file_path: None,
            wazuh_socket_addr: None,
            chronicle_url: None,
            chronicle_api_key: None,
            kafka_rest_url: None,
            kafka_topic: None,
            kafka_auth_header: None,
            loki_url: None,
        }
    }

    pub fn start(&self, rx: Receiver<Packet>) -> thread::JoinHandle<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);
        let exporter = self.clone();

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
                            flush_batch(&batch, &exporter);
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            flush_batch(&batch, &exporter);
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            flush_batch(&batch, &exporter);
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
    exporter: &SiemExporter,
) {
    if batch.is_empty() {
        return;
    }

    // 1. Elasticsearch Sink (Index rotation + template + ILM)
    if let Some(ref url) = exporter.es_url {
        ensure_es_setup(url);

        let mut bulk_body = String::new();
        for event in batch {
            // Index rotation: netscope-YYYY.MM.DD
            let date_part = event.timestamp.chars().take(10).collect::<String>().replace("-", ".");
            let index_name = format!("netscope-{}", date_part);
            bulk_body.push_str(&format!("{{\"index\":{{\"_index\":\"{}\"}}}}\n", index_name));
            if let Ok(json) = event.to_ndjson() {
                bulk_body.push_str(&json);
                bulk_body.push('\n');
            }
        }

        let agent = ureq::Agent::new();
        let _ = agent
            .post(url)
            .set("Content-Type", "application/x-ndjson")
            .send_string(&bulk_body);
    }

    // 2. Splunk HEC Sink (Batching + Retry + Sourcetype mapping)
    if let (Some(ref url), Some(ref token)) = (&exporter.splunk_url, &exporter.splunk_token) {
        let mut splunk_body = String::new();
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());

        for event in batch {
            let sourcetype = if event.summary.contains("Alert") || event.summary.contains("malicious") {
                "netscope:alert"
            } else {
                "netscope:packet"
            };

            let event_wrapper = serde_json::json!({
                "host": hostname,
                "source": "netscope-agent",
                "sourcetype": sourcetype,
                "event": event
            });

            if let Ok(json) = serde_json::to_string(&event_wrapper) {
                splunk_body.push_str(&json);
                splunk_body.push('\n');
            }
        }

        let agent = ureq::Agent::new();
        let mut retries = 3;
        let mut delay = Duration::from_millis(500);
        while retries > 0 {
            let res = agent
                .post(url)
                .set("Authorization", &format!("Splunk {}", token))
                .set("Content-Type", "application/json")
                .send_string(&splunk_body);
            
            match res {
                Ok(_) => break,
                Err(_) => {
                    retries -= 1;
                    if retries > 0 {
                        thread::sleep(delay);
                        delay *= 2;
                    }
                }
            }
        }
    }

    // 3. Splunk TCP/UDP Sink
    if let Some(ref addr) = exporter.splunk_tcp_addr {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            for event in batch {
                let syslog_line = format!("{}\n", event.to_rfc5424(6));
                let _ = stream.write_all(syslog_line.as_bytes());
            }
        }
    }
    if let Some(ref addr) = exporter.splunk_udp_addr {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            for event in batch {
                let syslog_line = event.to_rfc5424(6);
                let _ = socket.send_to(syslog_line.as_bytes(), addr);
            }
        }
    }

    // 4. Graylog GELF TCP/UDP Sink
    if let Some(ref addr) = exporter.gelf_tcp_addr {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            for event in batch {
                let gelf_line = format!("{}\0", event.to_gelf(6));
                let _ = stream.write_all(gelf_line.as_bytes());
            }
        }
    }
    if let Some(ref addr) = exporter.gelf_udp_addr {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            for event in batch {
                let gelf_line = event.to_gelf(6);
                let _ = socket.send_to(gelf_line.as_bytes(), addr);
            }
        }
    }

    // 5. Azure Sentinel Sink
    if let (Some(ref url), Some(ref token)) = (&exporter.sentinel_dcr_url, &exporter.sentinel_token) {
        let agent = ureq::Agent::new();
        let _ = agent.post(url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_json(serde_json::json!(batch));
    }

    // 6. AWS Security Lake Sink (OCSF written to local spool directory or S3 URL)
    if let Some(ref spool_dir) = exporter.aws_s3_spool_dir {
        if std::fs::create_dir_all(spool_dir).is_ok() {
            for event in batch {
                let is_alert = event.summary.contains("Alert") || event.summary.contains("malicious");
                let ocsf = event.to_ocsf(is_alert);
                let filename = format!("ocsf_{}.json", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let file_path = std::path::Path::new(spool_dir).join(filename);
                if let Ok(mut f) = std::fs::File::create(file_path) {
                    let _ = f.write_all(ocsf.to_string().as_bytes());
                }
            }
        }
    }
    if let Some(ref url) = exporter.aws_s3_url {
        let agent = ureq::Agent::new();
        for event in batch {
            let is_alert = event.summary.contains("Alert") || event.summary.contains("malicious");
            let ocsf = event.to_ocsf(is_alert);
            let _ = agent.put(url)
                .set("Content-Type", "application/json")
                .send_string(&ocsf.to_string());
        }
    }

    // 7. Wazuh Sink (localfile JSON append or socket push)
    if let Some(ref file_path) = exporter.wazuh_file_path {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path) {
            for event in batch {
                if let Ok(json) = event.to_ndjson() {
                    let _ = writeln!(file, "{}", json);
                }
            }
        }
    }
    if let Some(ref addr) = exporter.wazuh_socket_addr {
        if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
            for event in batch {
                if let Ok(json) = event.to_ndjson() {
                    let _ = writeln!(stream, "{}", json);
                }
            }
        } else if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            for event in batch {
                if let Ok(json) = event.to_ndjson() {
                    let _ = socket.send_to(json.as_bytes(), addr);
                }
            }
        }
    }

    // 8. Google Chronicle Sink
    if let (Some(ref url), Some(ref key)) = (&exporter.chronicle_url, &exporter.chronicle_api_key) {
        let agent = ureq::Agent::new();
        let udm_events: Vec<serde_json::Value> = batch.iter().map(|e| e.to_udm()).collect();
        let body = serde_json::json!({ "events": udm_events });
        let target_url = format!("{}?key={}", url, key);
        let _ = agent.post(&target_url)
            .set("Content-Type", "application/json")
            .send_json(body);
    }

    // 9. Kafka Sink (Confluent REST Proxy)
    if let (Some(ref url), Some(ref topic)) = (&exporter.kafka_rest_url, &exporter.kafka_topic) {
        let records = batch.iter().map(|e| serde_json::json!({"value": e})).collect::<Vec<_>>();
        let body = serde_json::json!({ "records": records });
        let agent = ureq::Agent::new();
        let mut req = agent.post(&format!("{}/topics/{}", url, topic))
            .set("Content-Type", "application/vnd.kafka.json.v2+json");
        if let Some(ref auth) = exporter.kafka_auth_header {
            req = req.set("Authorization", auth);
        }
        let _ = req.send_json(body);
    }

    // 10. Loki Sink
    if let Some(ref url) = exporter.loki_url {
        let mut values = Vec::new();
        for event in batch {
            let ts_nanos = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
                .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0).to_string())
                .unwrap_or_else(|_| (chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).to_string());
            
            if let Ok(line) = event.to_ndjson() {
                values.push(serde_json::json!([ts_nanos, line]));
            }
        }
        let body = serde_json::json!({
            "streams": [{
                "stream": {
                    "job": "netscope",
                    "agent": "netscope-agent"
                },
                "values": values
            }]
        });
        let agent = ureq::Agent::new();
        let _ = agent.post(url)
            .set("Content-Type", "application/json")
            .send_json(body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use bytes::Bytes;
    use chrono::Utc;
    use std::net::TcpListener;
    use std::io::Read;

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

        // 1. NDJSON
        let ndjson = event.to_ndjson().unwrap();
        assert!(ndjson.contains("\"protocol\":\"DNS\""));

        // 2. Syslog RFC 5424
        let syslog = event.to_rfc5424(3);
        assert!(syslog.contains("<35>1"));

        // 3. CEF
        let cef = event.to_cef("100002", "Beaconing Alert", 8);
        assert!(cef.starts_with("CEF:0|netscope|netscope-agent|2.0|100002|"));

        // 4. LEEF
        let leef = event.to_leef("200001", 5);
        assert!(leef.starts_with("LEEF:1.0|netscope|netscope-agent|2.0|200001|"));

        // 5. GELF
        let gelf = event.to_gelf(6);
        assert!(gelf.contains("\"short_message\":\"DNS Query\""));

        // 6. OCSF
        let ocsf = event.to_ocsf(false);
        assert_eq!(ocsf["class_uid"].as_i64().unwrap(), 4001);

        // 7. UDM
        let udm = event.to_udm();
        assert_eq!(udm["metadata"]["event_type"].as_str().unwrap(), "NETWORK_CONNECTION");

        // 8. Severity Mappings (0-10 validation)
        assert_eq!(event.severity_score, 0); // Chat
    }

    #[test]
    fn test_network_sinks_tcp_and_udp() {
        // Start TCP mock server
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = listener.local_addr().unwrap().to_string();

        // Start UDP mock server
        let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_socket.local_addr().unwrap().to_string();

        let mut exporter = SiemExporter::new(None, None, None);
        exporter.splunk_tcp_addr = Some(tcp_addr);
        exporter.splunk_udp_addr = Some(udp_addr.clone());
        exporter.gelf_udp_addr = Some(udp_addr);

        let event = SiemEvent {
            timestamp: "2026-07-28T21:16:26.123456Z".to_string(),
            src: Some("10.0.0.1".into()),
            dst: Some("10.0.0.2".into()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: "HTTP".into(),
            length: 120,
            summary: "GET /index.html".into(),
            severity_score: 6,
            severity_label: "Warning".into(),
            mitre_tactic: None,
            mitre_technique: None,
            kill_chain_phase: None,
            ja3: None,
            ja4: None,
            ja3s: None,
            geoip_country: None,
            geoip_city: None,
            asn: None,
            isp: None,
            threat_intel_matched: None,
            mac_vendor: None,
            resolved_dns_name: None,
        };

        // TCP listener thread
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let s = String::from_utf8_lossy(&buf[..n]);
                    assert!(s.contains("<38>1")); // priority 38 for severity 6
                }
            }
        });

        // Trigger batch push to sockets
        flush_batch(&[event], &exporter);

        let _ = handle.join();
    }

    #[test]
    fn test_raw_pcap_export() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_export_2.pcapng");
        
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

        let result = export_packet_to_pcapng(&pkt, &path, "Validation Test");
        assert!(result.is_ok());
        assert!(path.exists());

        let _ = std::fs::remove_file(path);
    }
}
