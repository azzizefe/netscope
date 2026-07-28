// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::models::Packet;
use crate::filter::Filter;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String, // "threshold", "anomaly", "signature", "correlation", "absence", "compound", "time-based"
    pub filter: String,
    pub group_by: Option<Vec<String>>,
    pub threshold: Option<usize>,
    pub window: Option<String>,
    pub sub_rules: Option<Vec<String>>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertRule {
    pub name: String,
    pub severity: String, // "informational", "low", "medium", "high"
    pub mitre_attack: Option<String>,
    pub kill_chain: Option<String>,
    pub trigger: RuleTrigger,
    pub actions: Vec<String>, // "alert", "block_src", "pcap_dump"
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub timestamp: String,
    pub rule_name: String,
    pub severity: String,
    pub msg: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub mitre_attack: Option<String>,
    pub kill_chain: Option<String>,
    pub actions_taken: Vec<String>,
    
    // Enrichments
    pub whois_info: Option<String>,
    pub dns_history: Option<String>,
    pub related_connections: Option<String>,
    pub historical_alerts_count_24h: usize,
}

pub struct AlertEngine {
    pub rules: Vec<AlertRule>,
    compiled_filters: HashMap<String, Filter>,
    
    // Threshold state: rule_name -> (src_ip, dst_ip) -> queue of matched timestamps
    threshold_history: HashMap<String, HashMap<(String, String), VecDeque<Instant>>>,
    
    // Absence state: rule_name -> last_seen_instant
    absence_history: HashMap<String, Instant>,
    
    // Correlation state: rule_name -> list of seen sub_rules triggered for src_ip
    correlation_state: HashMap<String, HashMap<String, Vec<String>>>,
    
    // Deduplication state: (rule_name, src_ip, dst_ip) -> last_triggered_instant
    dedup_history: HashMap<(String, String, String), Instant>,
    
    // Suppression settings
    pub suppressed_ips: HashSet<String>,
    
    // Historical alerts for enrichment: src_ip -> queue of alert timestamps
    alerts_history_24h: HashMap<String, VecDeque<DateTime<Utc>>>,
    
    // Multi-sensor state for correlation: dst_ip -> set of sensor_ids that scanned it
    sensor_scans: HashMap<String, HashSet<String>>,

    // Smart Alert states (2.2)
    pkt_rates: VecDeque<usize>,
    last_second: Instant,
    current_second_pkts: usize,

    http_error_rates: VecDeque<usize>,
    last_minute: Instant,
    current_minute_errors: usize,
    prev_minute_errors: usize,

    seen_ips: HashSet<String>,
    seen_protocols: HashSet<String>,
    beacon_timestamps: HashMap<(String, String), Vec<Instant>>,
    total_outbound_bytes: usize,
    lateral_destinations: HashMap<String, (Instant, HashSet<String>)>,
}

fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if s.ends_with('s') {
        let val: u64 = s[..s.len()-1].parse().unwrap_or(30);
        Duration::from_secs(val)
    } else if s.ends_with('m') {
        let val: u64 = s[..s.len()-1].parse().unwrap_or(1);
        Duration::from_secs(val * 60)
    } else if s.ends_with('h') {
        let val: u64 = s[..s.len()-1].parse().unwrap_or(1);
        Duration::from_secs(val * 3600)
    } else {
        Duration::from_secs(30)
    }
}

fn is_time_in_range(time_str: &str, start_str: &str, end_str: &str) -> bool {
    let parse_hm = |s: &str| -> Option<(u32, u32)> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            let h = parts[0].parse().ok()?;
            let m = parts[1].parse().ok()?;
            Some((h, m))
        } else {
            None
        }
    };
    if let (Some((sh, sm)), Some((eh, em))) = (parse_hm(start_str), parse_hm(end_str)) {
        if let Some((h, m)) = parse_hm(time_str) {
            let current = h * 60 + m;
            let start = sh * 60 + sm;
            let end = eh * 60 + em;
            if start <= end {
                current >= start && current <= end
            } else {
                current >= start || current <= end
            }
        } else {
            false
        }
    } else {
        false
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

impl AlertEngine {
    pub fn new(rules: Vec<AlertRule>) -> Self {
        let mut compiled_filters = HashMap::new();
        for rule in &rules {
            if let Ok(filter) = Filter::parse(&rule.trigger.filter) {
                compiled_filters.insert(rule.name.clone(), filter);
            }
        }
        AlertEngine {
            rules,
            compiled_filters,
            threshold_history: HashMap::new(),
            absence_history: HashMap::new(),
            correlation_state: HashMap::new(),
            dedup_history: HashMap::new(),
            suppressed_ips: HashSet::new(),
            alerts_history_24h: HashMap::new(),
            sensor_scans: HashMap::new(),
            pkt_rates: VecDeque::new(),
            last_second: Instant::now(),
            current_second_pkts: 0,
            http_error_rates: VecDeque::new(),
            last_minute: Instant::now(),
            current_minute_errors: 0,
            prev_minute_errors: 0,
            seen_ips: HashSet::new(),
            seen_protocols: HashSet::new(),
            beacon_timestamps: HashMap::new(),
            total_outbound_bytes: 0,
            lateral_destinations: HashMap::new(),
        }
    }

    pub fn check_packet(&mut self, pkt: &Packet, sensor_id: Option<&str>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = Instant::now();
        let now_utc = Utc::now();

        let rules = self.rules.clone();

        // ----------------------------------------------------
        // HEURISTIC / SMART ALERTS (2.2)
        // ----------------------------------------------------

        // 2.2.1 Traffic spike alert (3-sigma deviation)
        self.current_second_pkts += 1;
        if now.duration_since(self.last_second) >= Duration::from_secs(1) {
            self.pkt_rates.push_back(self.current_second_pkts);
            if self.pkt_rates.len() > 60 {
                self.pkt_rates.pop_front();
            }
            self.current_second_pkts = 0;
            self.last_second = now;

            if self.pkt_rates.len() >= 10 {
                let sum: usize = self.pkt_rates.iter().sum();
                let mean = sum as f64 / self.pkt_rates.len() as f64;
                let variance: f64 = self.pkt_rates.iter().map(|&x| {
                    let diff = x as f64 - mean;
                    diff * diff
                }).sum::<f64>() / self.pkt_rates.len() as f64;
                let std_dev = variance.sqrt();

                if self.pkt_rates.back().cloned().unwrap_or(0) as f64 > mean + 3.0 * std_dev {
                    if self.should_trigger_alert("Traffic Spike", "", "", now) {
                        alerts.push(self.create_smart_alert("Traffic Spike", "medium", format!("Traffic rate spike: 3-sigma exceeded. Current: {}, Mean: {:.2}", self.pkt_rates.back().unwrap_or(&0), mean), pkt));
                    }
                }
            }
        }

        // 2.2.2 Error burst alert
        let is_http_err = pkt.protocol.to_string().to_lowercase() == "http" && 
            (pkt.summary.contains("404") || pkt.summary.contains("500") || pkt.summary.contains("503") || pkt.summary.contains("400") || pkt.summary.contains("403"));
        if is_http_err {
            self.current_minute_errors += 1;
        }
        if now.duration_since(self.last_minute) >= Duration::from_secs(60) {
            self.prev_minute_errors = self.current_minute_errors;
            self.current_minute_errors = 0;
            self.last_minute = now;

            if self.prev_minute_errors > 5 {
                if self.should_trigger_alert("Error Burst", "", "", now) {
                    alerts.push(self.create_smart_alert("Error Burst", "high", format!("HTTP error burst: {} errors in 1 minute", self.prev_minute_errors), pkt));
                }
            }
        }

        // 2.2.3 New host alert
        if let Some(ref src) = pkt.src_addr {
            let ip_str = src.to_string();
            if !self.seen_ips.contains(&ip_str) {
                self.seen_ips.insert(ip_str.clone());
                if self.seen_ips.len() > 1 {
                    if self.should_trigger_alert("New Host Detected", &ip_str, "", now) {
                        alerts.push(self.create_smart_alert("New Host Detected", "low", format!("New host seen on network: {}", ip_str), pkt));
                    }
                }
            }
        }

        // 2.2.4 New protocol alert
        let proto_str = pkt.protocol.to_string();
        if !self.seen_protocols.contains(&proto_str) {
            self.seen_protocols.insert(proto_str.clone());
            if self.seen_protocols.len() > 1 {
                if self.should_trigger_alert("New Protocol Detected", "", "", now) {
                    alerts.push(self.create_smart_alert("New Protocol Detected", "low", format!("New protocol seen on network: {}", proto_str), pkt));
                }
            }
        }

        // 2.2.5 Beaconing alert
        if let (Some(src), Some(dst)) = (pkt.src_addr, pkt.dst_addr) {
            let key = (src.to_string(), dst.to_string());
            let timestamps = self.beacon_timestamps.entry(key.clone()).or_default();
            timestamps.push(now);
            if timestamps.len() > 5 {
                timestamps.remove(0);
            }
            if timestamps.len() == 5 {
                let mut intervals = Vec::new();
                for i in 0..4 {
                    intervals.push(timestamps[i+1].duration_since(timestamps[i]).as_secs_f64());
                }
                let mean: f64 = intervals.iter().sum::<f64>() / 4.0;
                let variance: f64 = intervals.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / 4.0;
                if variance < 0.05 && mean > 0.5 {
                    if self.should_trigger_alert("Beaconing Detected", &key.0, &key.1, now) {
                        alerts.push(self.create_smart_alert("Beaconing Detected", "high", format!("C2 beaconing behavior detected: mean interval {:.2}s, variance {:.4}", mean, variance), pkt));
                    }
                }
            }
        }

        // 2.2.6 Data exfiltration alert
        self.total_outbound_bytes += pkt.length;
        if self.total_outbound_bytes > 100_000_000 {
            if self.should_trigger_alert("Data Exfiltration", "", "", now) {
                alerts.push(self.create_smart_alert("Data Exfiltration", "high", "Potential data exfiltration: outbound traffic exceeded 100MB threshold".to_string(), pkt));
            }
        }

        // 2.2.7 Privilege escalation alert
        if let (Some(src_p), Some(dst_p)) = (pkt.src_port, pkt.dst_port) {
            if (dst_p == 22 || dst_p == 3389 || dst_p == 445) && src_p < 1024 {
                if self.should_trigger_alert("Privilege Escalation", "", "", now) {
                    alerts.push(self.create_smart_alert("Privilege Escalation", "high", format!("Privilege escalation alert: low port {} connected to high-value service port {}", src_p, dst_p), pkt));
                }
            }
        }

        // 2.2.8 Lateral movement alert
        let is_lateral_movement = if let (Some(src), Some(dst)) = (pkt.src_addr, pkt.dst_addr) {
            let src_str = src.to_string();
            let dst_str = dst.to_string();
            let entry = self.lateral_destinations.entry(src_str.clone()).or_insert_with(|| (now, HashSet::new()));
            if now.duration_since(entry.0) > Duration::from_secs(10) {
                entry.0 = now;
                entry.1.clear();
            }
            entry.1.insert(dst_str);
            entry.1.len() >= 5
        } else {
            false
        };

        if is_lateral_movement {
            if let Some(ref src) = pkt.src_addr {
                let src_str = src.to_string();
                if self.should_trigger_alert("Lateral Movement", &src_str, "", now) {
                    let targets_count = self.lateral_destinations.get(&src_str).map(|(_, h)| h.len()).unwrap_or(0);
                    alerts.push(self.create_smart_alert("Lateral Movement", "high", format!("Lateral movement warning: host connected to {} internal targets", targets_count), pkt));
                }
            }
        }

        // 2.2.9 DNS tunneling alert
        let is_dns = pkt.protocol.to_string().to_lowercase() == "dns";
        if is_dns && pkt.summary.len() > 60 {
            if self.should_trigger_alert("DNS Tunneling", "", "", now) {
                alerts.push(self.create_smart_alert("DNS Tunneling", "high", format!("Suspicious DNS Tunneling: domain or query name size is {} chars", pkt.summary.len()), pkt));
            }
        }

        // 2.2.10 DGA domain alert
        if is_dns {
            let domain = pkt.summary.split_whitespace().last().unwrap_or("");
            if !domain.is_empty() && shannon_entropy(domain) > 4.2 {
                if self.should_trigger_alert("DGA Domain", "", "", now) {
                    alerts.push(self.create_smart_alert("DGA Domain", "medium", format!("DGA domain detected with high Shannon entropy ({:.2}): {}", shannon_entropy(domain), domain), pkt));
                }
            }
        }

        // 2.2.11 Encrypted traffic anomaly
        let is_tls = pkt.protocol.to_string().to_lowercase() == "tls";
        let is_http = pkt.protocol.to_string().to_lowercase() == "http";
        let is_anomaly = (is_tls && pkt.dst_port == Some(80)) || (is_http && pkt.dst_port == Some(443));
        if is_anomaly {
            if self.should_trigger_alert("Encrypted Traffic Anomaly", "", "", now) {
                alerts.push(self.create_smart_alert("Encrypted Traffic Anomaly", "medium", "Encrypted traffic anomaly: TLS on port 80 or plaintext HTTP on port 443".to_string(), pkt));
            }
        }

        // 2.2.12 Expired certificate alert
        let has_expired_cert = is_tls && pkt.summary.to_lowercase().contains("expired");
        if has_expired_cert {
            if self.should_trigger_alert("Expired Certificate", "", "", now) {
                alerts.push(self.create_smart_alert("Expired Certificate", "medium", "TLS session established using expired security certificate".to_string(), pkt));
            }
        }

        // 2.2.13 Weak cipher alert
        let has_weak_cipher = is_tls && (pkt.summary.contains("TLS 1.0") || pkt.summary.contains("TLS 1.1") || pkt.summary.contains("RC4") || pkt.summary.contains("3DES") || pkt.summary.contains("MD5"));
        if has_weak_cipher {
            if self.should_trigger_alert("Weak Cipher Alert", "", "", now) {
                alerts.push(self.create_smart_alert("Weak Cipher Alert", "medium", "TLS connection negotiated using obsolete/weak cryptographic algorithms".to_string(), pkt));
            }
        }

        // 2.2.14 PQC migration gap alert
        let has_pqc_gap = is_tls && pkt.dst_port == Some(443) && !pkt.summary.to_lowercase().contains("kyber") && !pkt.summary.to_lowercase().contains("ml-kem");
        if has_pqc_gap {
            if self.should_trigger_alert("PQC Migration Gap", "", "", now) {
                alerts.push(self.create_smart_alert("PQC Migration Gap", "low", "TLS 1.3 connection to HTTPS without Post-Quantum Cryptography (ML-KEM/Kyber)".to_string(), pkt));
            }
        }

        // ----------------------------------------------------
        // STATIC RULE DSL MATCHES
        // ----------------------------------------------------

        // Check each rule
        for rule in &rules {
            let src_str = pkt.src_addr.map(|a| a.to_string()).unwrap_or_default();
            let dst_str = pkt.dst_addr.map(|a| a.to_string()).unwrap_or_default();

            if self.suppressed_ips.contains(&src_str) || self.suppressed_ips.contains(&dst_str) {
                continue;
            }

            let filter = match self.compiled_filters.get(&rule.name) {
                Some(f) => f,
                None => continue,
            };

            let matches = filter.matches(pkt);

            if matches && rule.trigger.trigger_type == "absence" {
                self.absence_history.insert(rule.name.clone(), now);
            }

            match rule.trigger.trigger_type.as_str() {
                "threshold" | "anomaly" | "time-based" => {
                    if matches {
                        let window_dur = parse_duration(rule.trigger.window.as_deref().unwrap_or("30s"));
                        
                        let mut limit = rule.trigger.threshold.unwrap_or(50);
                        if rule.trigger.trigger_type == "time-based" {
                            let current_time_str = pkt.timestamp.format("%H:%M").to_string();
                            let start = rule.trigger.start_time.as_deref().unwrap_or("18:00");
                            let end = rule.trigger.end_time.as_deref().unwrap_or("08:00");
                            if is_time_in_range(&current_time_str, start, end) {
                                limit = (limit / 2).max(1);
                            }
                        }

                        let key = (src_str.clone(), dst_str.clone());
                        let limit_reached = {
                            let rule_hist = self.threshold_history.entry(rule.name.clone()).or_default();
                            let queue = rule_hist.entry(key.clone()).or_default();
                            
                            queue.push_back(now);
                            while let Some(&first) = queue.front() {
                                if now.duration_since(first) > window_dur {
                                    queue.pop_front();
                                } else {
                                    break;
                                }
                            }
                            queue.len() >= limit
                        };

                        if limit_reached {
                            if self.should_trigger_alert(&rule.name, &src_str, &dst_str, now) {
                                let queue_len = self.threshold_history.get(&rule.name)
                                    .and_then(|h| h.get(&key))
                                    .map(|q| q.len())
                                    .unwrap_or(0);
                                let alert = self.create_alert(rule, pkt, format!("Threshold exceeded: {} events", queue_len));
                                alerts.push(alert);
                                if let Some(rule_hist) = self.threshold_history.get_mut(&rule.name) {
                                    if let Some(queue) = rule_hist.get_mut(&key) {
                                        queue.clear();
                                    }
                                }
                            }
                        }
                    }
                }
                "signature" => {
                    if matches {
                        if self.should_trigger_alert(&rule.name, &src_str, &dst_str, now) {
                            let alert = self.create_alert(rule, pkt, format!("Signature matched rule: {}", rule.name));
                            alerts.push(alert);
                        }
                    }
                }
                "correlation" => {
                    if matches {
                        if let Some(ref sub_rules) = rule.trigger.sub_rules {
                            let seq_matched = {
                                let src_states = self.correlation_state.entry(rule.name.clone()).or_default();
                                let seen = src_states.entry(src_str.clone()).or_default();
                                
                                for sub in sub_rules {
                                    if pkt.summary.contains(sub) && !seen.contains(sub) {
                                        seen.push(sub.clone());
                                    }
                                }
                                seen.len() == sub_rules.len()
                            };

                            if seq_matched {
                                if self.should_trigger_alert(&rule.name, &src_str, &dst_str, now) {
                                    let seen_list = self.correlation_state.get(&rule.name)
                                        .and_then(|h| h.get(&src_str))
                                        .cloned()
                                        .unwrap_or_default();
                                    let alert = self.create_alert(rule, pkt, format!("Correlated sequence detected: {:?}", seen_list));
                                    alerts.push(alert);
                                    if let Some(src_states) = self.correlation_state.get_mut(&rule.name) {
                                        if let Some(seen) = src_states.get_mut(&src_str) {
                                            seen.clear();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }

            let is_distributed_scanning = if matches && sensor_id.is_some() && !dst_str.is_empty() {
                let s_id = sensor_id.unwrap().to_string();
                let sensors = self.sensor_scans.entry(dst_str.clone()).or_default();
                sensors.insert(s_id);
                sensors.len() >= 3
            } else {
                false
            };

            if is_distributed_scanning {
                if self.should_trigger_alert(&"Distributed Scanning".to_string(), &src_str, &dst_str, now) {
                    let sensors = self.sensor_scans.get(&dst_str).cloned().unwrap_or_default();
                    let correlated_rule = AlertRule {
                        name: "Distributed Scanning".to_string(),
                        severity: "high".to_string(),
                        mitre_attack: Some("T1595".to_string()),
                        kill_chain: Some("Recon".to_string()),
                        trigger: rule.trigger.clone(),
                        actions: vec!["alert".into(), "block_src".into()],
                    };
                    let alert = self.create_alert(&correlated_rule, pkt, format!("Distributed scanning target IP from sensors: {:?}", sensors));
                    alerts.push(alert);
                    self.sensor_scans.remove(&dst_str);
                }
            }
        }

        // Check absence rules
        let absence_rules: Vec<AlertRule> = rules.iter().filter(|r| r.trigger.trigger_type == "absence").cloned().collect();
        for rule in &absence_rules {
            let window_dur = parse_duration(rule.trigger.window.as_deref().unwrap_or("30s"));
            let last_seen = self.absence_history.entry(rule.name.clone()).or_insert(now);
            if now.duration_since(*last_seen) > window_dur {
                if self.should_trigger_alert(&rule.name, &"".to_string(), &"".to_string(), now) {
                    let dummy_pkt = Packet {
                        timestamp: now_utc,
                        src_addr: None,
                        dst_addr: None,
                        src_port: None,
                        dst_port: None,
                        protocol: crate::registry::Protocol::Unknown("".to_string()),
                        length: 0,
                        summary: "Absence event triggered".to_string(),
                        data: bytes::Bytes::new(),
                        llm: None,
                    };
                    let alert = self.create_alert(rule, &dummy_pkt, format!("Absence triggered: no matching traffic seen for {:?}", window_dur));
                    alerts.push(alert);
                    self.absence_history.insert(rule.name.clone(), now); // Reset timer
                }
            }
        }

        // Record historical counts for enrichment
        for alert in &alerts {
            if let Some(ref src) = alert.src_ip {
                let history = self.alerts_history_24h.entry(src.clone()).or_default();
                history.push_back(now_utc);
            }
        }

        alerts
    }

    fn should_trigger_alert(&mut self, rule_name: &str, src: &str, dst: &str, now: Instant) -> bool {
        let key = (rule_name.to_string(), src.to_string(), dst.to_string());
        if let Some(&last) = self.dedup_history.get(&key) {
            if now.duration_since(last) < Duration::from_secs(10) {
                return false;
            }
        }
        self.dedup_history.insert(key, now);
        true
    }

    fn create_alert(&self, rule: &AlertRule, pkt: &Packet, msg: String) -> Alert {
        let src_str = pkt.src_addr.map(|a| a.to_string());
        let dst_str = pkt.dst_addr.map(|a| a.to_string());
        let now_utc = Utc::now();

        // WHOIS lookup
        let whois_info = src_str.as_ref().map(|ip| {
            if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.") {
                "Private Network (RFC 1918)".to_string()
            } else {
                format!("Simulated WHOIS for {}: Owner: Netscope, Registrar: IANA", ip)
            }
        });

        // Passive DNS
        let dns_history = dst_str.as_ref().and_then(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                crate::siem::global_name_cache().lock().unwrap().name_for(addr).map(|s| s.to_string())
            } else {
                None
            }
        });

        // 24 Hour alert count
        let count = src_str.as_ref().map(|src| {
            if let Some(history) = self.alerts_history_24h.get(src) {
                let mut valid = 0;
                for t in history {
                    if now_utc.signed_duration_since(*t).num_hours() < 24 {
                        valid += 1;
                    }
                }
                valid
            } else {
                0
            }
        }).unwrap_or(0);

        Alert {
            timestamp: now_utc.to_rfc3339(),
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            msg,
            src_ip: src_str.clone(),
            dst_ip: dst_str.clone(),
            mitre_attack: rule.mitre_attack.clone(),
            kill_chain: rule.kill_chain.clone(),
            actions_taken: rule.actions.clone(),
            whois_info,
            dns_history,
            related_connections: Some(format!("Related connection: {} -> {}", src_str.unwrap_or_default(), dst_str.unwrap_or_default())),
            historical_alerts_count_24h: count,
        }
    }

    fn create_smart_alert(&self, rule_name: &str, severity: &str, msg: String, pkt: &Packet) -> Alert {
        let src_str = pkt.src_addr.map(|a| a.to_string());
        let dst_str = pkt.dst_addr.map(|a| a.to_string());
        let now_utc = Utc::now();

        let whois_info = src_str.as_ref().map(|ip| {
            if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.") {
                "Private Network (RFC 1918)".to_string()
            } else {
                format!("Simulated WHOIS for {}: Owner: Netscope, Registrar: IANA", ip)
            }
        });

        let dns_history = dst_str.as_ref().and_then(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                crate::siem::global_name_cache().lock().unwrap().name_for(addr).map(|s| s.to_string())
            } else {
                None
            }
        });

        Alert {
            timestamp: now_utc.to_rfc3339(),
            rule_name: rule_name.to_string(),
            severity: severity.to_string(),
            msg,
            src_ip: src_str,
            dst_ip: dst_str,
            mitre_attack: None,
            kill_chain: None,
            actions_taken: vec!["alert".to_string()],
            whois_info,
            dns_history,
            related_connections: None,
            historical_alerts_count_24h: 0,
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
    fn test_threshold_and_deduplication() {
        let rule = AlertRule {
            name: "Threshold Alert Test".to_string(),
            severity: "high".to_string(),
            mitre_attack: Some("T1046".to_string()),
            kill_chain: Some("Recon".to_string()),
            trigger: RuleTrigger {
                trigger_type: "threshold".to_string(),
                filter: "tcp.port == 80".to_string(),
                group_by: Some(vec!["src".into(), "dst".into()]),
                threshold: Some(3),
                window: Some("10s".into()),
                sub_rules: None,
                start_time: None,
                end_time: None,
            },
            actions: vec!["alert".to_string()],
        };

        let mut engine = AlertEngine::new(vec![rule]);
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.1".parse().unwrap()),
            dst_addr: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 60,
            summary: "HTTP GET".to_string(),
            data: Bytes::new(),
            llm: None,
        };

        // First packet - no alert
        let alerts = engine.check_packet(&pkt, None);
        assert!(alerts.is_empty());

        // Second packet - no alert
        let alerts = engine.check_packet(&pkt, None);
        assert!(alerts.is_empty());

        // Third packet - threshold triggered!
        let alerts = engine.check_packet(&pkt, None);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "Threshold Alert Test");

        // Fourth packet immediately - suppressed due to deduplication (10s)
        let alerts = engine.check_packet(&pkt, None);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_alert_suppression() {
        let rule = AlertRule {
            name: "Signature Alert Test".to_string(),
            severity: "high".to_string(),
            mitre_attack: None,
            kill_chain: None,
            trigger: RuleTrigger {
                trigger_type: "signature".to_string(),
                filter: "tcp.port == 80".to_string(),
                group_by: None,
                threshold: None,
                window: None,
                sub_rules: None,
                start_time: None,
                end_time: None,
            },
            actions: vec!["alert".to_string()],
        };

        let mut engine = AlertEngine::new(vec![rule]);
        engine.suppressed_ips.insert("192.168.1.100".to_string());

        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.100".parse().unwrap()), // Suppressed IP
            dst_addr: Some("8.8.8.8".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 60,
            summary: "GET /".to_string(),
            data: Bytes::new(),
            llm: None,
        };

        let alerts = engine.check_packet(&pkt, None);
        assert!(alerts.is_empty()); // Suppressed!
    }

    #[test]
    fn test_smart_alerts() {
        let mut engine = AlertEngine::new(vec![]);

        // 1. First packet to populate seen lists
        let pkt1 = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.9".parse().unwrap()),
            dst_addr: Some("10.0.0.10".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 100,
            summary: "HTTP GET /".to_string(),
            data: Bytes::new(),
            llm: None,
        };
        let _ = engine.check_packet(&pkt1, None);

        // Second packet with a new host
        let pkt2 = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.11".parse().unwrap()),
            dst_addr: Some("10.0.0.10".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 100,
            summary: "HTTP GET /".to_string(),
            data: Bytes::new(),
            llm: None,
        };
        let alerts = engine.check_packet(&pkt2, None);
        assert!(alerts.iter().any(|a| a.rule_name == "New Host Detected"));

        // 2. DNS Tunneling
        let long_dns_pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.9".parse().unwrap()),
            dst_addr: Some("10.0.0.10".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(53),
            protocol: Protocol::Dns,
            length: 100,
            summary: "DNS Query for aaaaaabbbbbbccccccddddddeeeeeeffffffgggggghhhhhhiiiiii.com".to_string(),
            data: Bytes::new(),
            llm: None,
        };
        let alerts = engine.check_packet(&long_dns_pkt, None);
        assert!(alerts.iter().any(|a| a.rule_name == "DNS Tunneling"));

        // 3. Encrypted Anomaly
        let anomaly_pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.9".parse().unwrap()),
            dst_addr: Some("10.0.0.10".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Tls,
            length: 100,
            summary: "TLS ClientHello".to_string(),
            data: Bytes::new(),
            llm: None,
        };
        let alerts = engine.check_packet(&anomaly_pkt, None);
        assert!(alerts.iter().any(|a| a.rule_name == "Encrypted Traffic Anomaly"));

        // 4. Privilege Escalation
        let priv_esc_pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.9".parse().unwrap()),
            dst_addr: Some("10.0.0.10".parse().unwrap()),
            src_port: Some(80), // Low port
            dst_port: Some(22), // SSH
            protocol: Protocol::Ssh,
            length: 100,
            summary: "SSH Connection".to_string(),
            data: Bytes::new(),
            llm: None,
        };
        let alerts = engine.check_packet(&priv_esc_pkt, None);
        assert!(alerts.iter().any(|a| a.rule_name == "Privilege Escalation"));
    }
}
