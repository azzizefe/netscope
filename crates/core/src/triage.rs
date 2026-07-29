// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! 100% Offline Deterministic Risk Scoring & Automated Local Triage Engine (§6.2).
//!
//! Provides zero-token, zero-LLM local triage and risk scoring:
//! - Local feature extraction (duration, bytes, packets, TCP flags, payload entropy)
//! - Weighted risk scoring (0 - 100 Risk Score)
//! - Automated local triage classification (Info, Low, Medium, High, Critical)
//! - Whitelist & False Positive (FP) suppression filter
//! - 100% Native Rust zero-external API dependency execution

use std::collections::HashSet;
use std::net::IpAddr;

use crate::baseline::calculate_shannon_entropy;
use crate::models::{Packet, Protocol};

/// Local connection feature vector extracted per connection/packet (§6.2.1).
#[derive(Debug, Clone)]
pub struct ConnectionFeatures {
    pub duration_secs: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub tcp_syn: bool,
    pub tcp_ack: bool,
    pub tcp_rst: bool,
    pub tcp_fin: bool,
    pub payload_entropy: f64,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl Default for ConnectionFeatures {
    fn default() -> Self {
        Self {
            duration_secs: 0.0,
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
            tcp_syn: false,
            tcp_ack: false,
            tcp_rst: false,
            tcp_fin: false,
            payload_entropy: 0.0,
            dst_port: 0,
            protocol: Protocol::Unknown("unknown".to_string()),
        }
    }
}

impl ConnectionFeatures {
    pub fn from_packet(pkt: &Packet) -> Self {
        let entropy = calculate_shannon_entropy(&pkt.data);
        Self {
            duration_secs: 0.001,
            bytes_sent: pkt.length as u64,
            bytes_recv: 0,
            packets_sent: 1,
            packets_recv: 0,
            tcp_syn: pkt.summary.contains("SYN"),
            tcp_ack: pkt.summary.contains("ACK"),
            tcp_rst: pkt.summary.contains("RST"),
            tcp_fin: pkt.summary.contains("FIN"),
            payload_entropy: entropy,
            dst_port: pkt.dst_port.unwrap_or(0),
            protocol: pkt.protocol.clone(),
        }
    }
}

/// Triage severity classification (§6.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TriageSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl TriageSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            TriageSeverity::Info => "INFO",
            TriageSeverity::Low => "LOW",
            TriageSeverity::Medium => "MEDIUM",
            TriageSeverity::High => "HIGH",
            TriageSeverity::Critical => "CRITICAL",
        }
    }
}

/// Triage decision & risk score report (§6.2.2, §6.2.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalTriageResult {
    /// Risk Score between 0 and 100 (§6.2.2).
    pub risk_score: u8,
    pub severity: TriageSeverity,
    pub is_suppressed: bool,
    pub reasons: Vec<String>,
    pub recommended_action: String,
}

/// Whitelist & False Positive (FP) suppression filter (§6.2.4).
#[derive(Debug, Clone, Default)]
pub struct WhitelistFilter {
    pub allowed_ips: HashSet<IpAddr>,
    pub allowed_ports: HashSet<u16>,
    pub suppressed_sids: HashSet<u64>,
}

impl WhitelistFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_whitelisted(&self, ip: Option<IpAddr>, port: Option<u16>, sid: Option<u64>) -> bool {
        if let Some(ip_addr) = ip {
            if self.allowed_ips.contains(&ip_addr) {
                return true;
            }
        }
        if let Some(p) = port {
            if self.allowed_ports.contains(&p) {
                return true;
            }
        }
        if let Some(s) = sid {
            if self.suppressed_sids.contains(&s) {
                return true;
            }
        }
        false
    }
}

/// 100% Native Rust Deterministic Triage Engine (§6.2.5).
#[derive(Debug, Default)]
pub struct DeterministicTriageEngine {
    pub whitelist: WhitelistFilter,
}

impl DeterministicTriageEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates features and generates a zero-token risk score & triage result (§6.2.2, §6.2.3).
    pub fn evaluate(
        &self,
        features: &ConnectionFeatures,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        sid: Option<u64>,
        base_alert_msg: Option<&str>,
    ) -> LocalTriageResult {
        // Check whitelist suppression (§6.2.4)
        let is_suppressed = self
            .whitelist
            .is_whitelisted(src_ip, Some(features.dst_port), sid)
            || self
                .whitelist
                .is_whitelisted(dst_ip, Some(features.dst_port), sid);

        let mut risk_score: u32 = 0;
        let mut reasons = Vec::new();

        if let Some(msg) = base_alert_msg {
            risk_score += 40;
            reasons.push(format!("IDS Alert triggered: {msg}"));
        }

        // Sensitive port assessment
        if [22, 23, 3389, 445, 1433, 3306].contains(&features.dst_port) {
            risk_score += 15;
            reasons.push(format!(
                "Sensitive administrative/database port access ({})",
                features.dst_port
            ));
        }

        // High entropy payload check
        if features.payload_entropy > 7.5 && features.bytes_sent > 200 {
            risk_score += 25;
            reasons.push(format!(
                "High entropy payload ({:.2} bits/byte)",
                features.payload_entropy
            ));
        }

        // Abnormal TCP flags (e.g. RST/SYN anomalies)
        if features.tcp_rst && !features.tcp_ack {
            risk_score += 10;
            reasons.push("Unusual TCP RST flag without ACK".to_string());
        }

        let final_score = (risk_score.min(100)) as u8;

        let severity = match final_score {
            0..=20 => TriageSeverity::Info,
            21..=45 => TriageSeverity::Low,
            46..=70 => TriageSeverity::Medium,
            71..=89 => TriageSeverity::High,
            _ => TriageSeverity::Critical,
        };

        let recommended_action = match severity {
            TriageSeverity::Critical => "Immediate containment & block IP",
            TriageSeverity::High => "Isolate endpoint & escalate to Tier 2 SOC Analyst",
            TriageSeverity::Medium => "Monitor host connection pattern & verify credentials",
            TriageSeverity::Low => "Log event for hourly trend analysis",
            TriageSeverity::Info => "No action required (informational event)",
        }
        .to_string();

        LocalTriageResult {
            risk_score: final_score,
            severity,
            is_suppressed,
            reasons,
            recommended_action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;

    #[test]
    fn test_feature_extraction() {
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.5".parse().unwrap()),
            dst_addr: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(22),
            protocol: Protocol::Ssh,
            length: 150,
            summary: "SSH SYN".to_string(),
            data: Bytes::from(vec![0x00; 150]),
            llm: None,
        };

        let feat = ConnectionFeatures::from_packet(&pkt);
        assert_eq!(feat.dst_port, 22);
        assert!(feat.tcp_syn);
        assert_eq!(feat.payload_entropy, 0.0);
    }

    #[test]
    fn test_deterministic_risk_scoring() {
        let engine = DeterministicTriageEngine::new();
        let feat = ConnectionFeatures {
            duration_secs: 0.1,
            bytes_sent: 500,
            bytes_recv: 500,
            packets_sent: 5,
            packets_recv: 5,
            tcp_syn: true,
            tcp_ack: true,
            tcp_rst: false,
            tcp_fin: false,
            payload_entropy: 7.8,
            dst_port: 3389,
            protocol: Protocol::Rdp,
        };

        let res = engine.evaluate(
            &feat,
            None,
            None,
            Some(10001),
            Some("RDP Brute Force Attempt"),
        );
        assert!(res.risk_score >= 70);
        assert_eq!(res.severity, TriageSeverity::High);
        assert!(!res.is_suppressed);
    }

    #[test]
    fn test_whitelist_suppression() {
        let mut engine = DeterministicTriageEngine::new();
        let trusted_ip: IpAddr = "192.168.1.100".parse().unwrap();
        engine.whitelist.allowed_ips.insert(trusted_ip);

        let feat = ConnectionFeatures::default();
        let res = engine.evaluate(&feat, Some(trusted_ip), None, None, None);
        assert!(res.is_suppressed);
    }
}
