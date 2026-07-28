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
        }
    }

    pub fn check_packet(&mut self, pkt: &Packet, sensor_id: Option<&str>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = Instant::now();
        let now_utc = Utc::now();

        let rules = self.rules.clone();

        // Check each rule
        for rule in &rules {
            let src_str = pkt.src_addr.map(|a| a.to_string()).unwrap_or_default();
            let dst_str = pkt.dst_addr.map(|a| a.to_string()).unwrap_or_default();

            // 1. Alert suppression (2.1.4)
            if self.suppressed_ips.contains(&src_str) || self.suppressed_ips.contains(&dst_str) {
                continue;
            }

            let filter = match self.compiled_filters.get(&rule.name) {
                Some(f) => f,
                None => continue,
            };

            let matches = filter.matches(pkt);

            // Update absence tracker if filter matches
            if matches && rule.trigger.trigger_type == "absence" {
                self.absence_history.insert(rule.name.clone(), now);
            }

            match rule.trigger.trigger_type.as_str() {
                "threshold" | "anomaly" | "time-based" => {
                    if matches {
                        let window_dur = parse_duration(rule.trigger.window.as_deref().unwrap_or("30s"));
                        
                        // Custom threshold override for time-based rules
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

            // Multi-sensor correlation engine (2.1.6)
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

        // Check absence rules (2.1.2)
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

        // Record historical counts for enrichment (2.1.5)
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
            // Deduplication (2.1.3): 10 seconds interval
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

        // WHOIS lookup (2.1.5)
        let whois_info = src_str.as_ref().map(|ip| {
            if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.") {
                "Private Network (RFC 1918)".to_string()
            } else {
                format!("Simulated WHOIS for {}: Owner: Netscope, Registrar: IANA", ip)
            }
        });

        // Passive DNS (2.1.5)
        let dns_history = dst_str.as_ref().and_then(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                crate::siem::global_name_cache().lock().unwrap().name_for(addr).map(|s| s.to_string())
            } else {
                None
            }
        });

        // 24 Hour alert count (2.1.5)
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
}
