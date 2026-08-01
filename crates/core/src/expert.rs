// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Senior Protocol Expert & Diagnostic Engine.
//!
//! Provides Wireshark-like Expert Info classification, stateful flow health scoring,
//! RTT latency tracking, TCP sequence anomaly analysis, protocol semantic validation,
//! and senior protocol research diagnostics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::models::Packet;

/// Severity levels matching industry standard Wireshark Expert Info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExpertSeverity {
    Chat,
    Note,
    Warning,
    Error,
}

impl ExpertSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chat => "Chat",
            Self::Note => "Note",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }
}

/// Category grouping for protocol expert diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpertGroup {
    Sequence,
    Checksum,
    Latency,
    Security,
    Malformed,
    ProtocolViolation,
    FlowControl,
    Crypto,
    General,
}

impl ExpertGroup {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sequence => "Sequence & ACKs",
            Self::Checksum => "Checksum Integrity",
            Self::Latency => "Latency & RTT",
            Self::Security => "Security & Threat",
            Self::Malformed => "Malformed Packet",
            Self::ProtocolViolation => "Protocol State Violation",
            Self::FlowControl => "Flow Control & Windowing",
            Self::Crypto => "Cryptography & Handshake",
            Self::General => "General Protocol",
        }
    }
}

/// Detailed protocol diagnostic finding for senior researchers and SOC analysts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolDiagnosticInfo {
    pub severity: ExpertSeverity,
    pub group: ExpertGroup,
    pub protocol: String,
    pub title: String,
    pub summary: String,
    pub explanation: String,
    pub recommended_action: String,
}

/// Aggregated protocol health and performance summary for a network flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowExpertSummary {
    pub flow_key: String,
    pub total_packets: usize,
    pub total_bytes: usize,
    pub health_score: f64, // 0.0 (severely degraded) to 100.0 (perfect)
    pub avg_rtt_ms: f64,
    pub packet_loss_rate_pct: f64,
    pub retransmission_count: usize,
    pub out_of_order_count: usize,
    pub zero_window_events: usize,
    pub diagnostics: Vec<ProtocolDiagnosticInfo>,
    pub severity_breakdown: BTreeMap<String, usize>,
}

/// Senior Protocol Expert Engine.
pub struct ProtocolExpertEngine;

impl ProtocolExpertEngine {
    /// Deeply analyze a single packet and generate senior protocol expert diagnostics.
    pub fn analyze_packet(pkt: &Packet) -> Vec<ProtocolDiagnosticInfo> {
        let mut diags = Vec::new();
        let s = &pkt.summary;
        let proto = pkt.protocol.to_string();

        // Checksum & Integrity
        if s.contains("bad checksum")
            || s.contains("Bad checksum")
            || s.contains("checksum mismatch")
        {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Error,
                group: ExpertGroup::Checksum,
                protocol: proto.clone(),
                title: "Corrupted Header Checksum".to_string(),
                summary: s.clone(),
                explanation: "Packet payload or header failed integrity verification. Likely caused by network interface card (NIC) hardware corruption or middlebox modification.".to_string(),
                recommended_action: "Verify NIC checksum offload settings and check intermediate switches for bad cabling or memory corruption.".to_string(),
            });
        }

        // Malformed & Truncation
        if s.contains("Malformed") || s.contains("truncated") || s.contains("(short frame)") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Error,
                group: ExpertGroup::Malformed,
                protocol: proto.clone(),
                title: "Malformed Protocol Framing".to_string(),
                summary: s.clone(),
                explanation: "PDU length declared in header exceeds available packet bytes, or mandatory protocol fields are truncated.".to_string(),
                recommended_action: "Inspect raw packet bytes with DPI engine to check for fuzzing attempts or custom non-standard protocol implementations.".to_string(),
            });
        }

        // Sequence & Loss Diagnostics
        if s.contains("[TCP Retransmission]") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Warning,
                group: ExpertGroup::Sequence,
                protocol: proto.clone(),
                title: "TCP Packet Retransmission".to_string(),
                summary: s.clone(),
                explanation: "Sender re-transmitted data segment because ACK was not received within Retransmission Timeout (RTO). Indicates network packet drop or severe congestion.".to_string(),
                recommended_action: "Monitor path packet loss, check router queue drops, and evaluate TCP window scaling.".to_string(),
            });
        }

        if s.contains("[TCP Dup ACK") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Warning,
                group: ExpertGroup::Sequence,
                protocol: proto.clone(),
                title: "TCP Duplicate Acknowledgement".to_string(),
                summary: s.clone(),
                explanation: "Receiver sent duplicate ACK indicating gap in expected sequence numbers. Sender may trigger Fast Retransmit.".to_string(),
                recommended_action: "Check for out-of-order delivery or selective packet loss on high-throughput link.".to_string(),
            });
        }

        if s.contains("[TCP Out-of-Order]") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Warning,
                group: ExpertGroup::Sequence,
                protocol: proto.clone(),
                title: "TCP Out-of-Order Segment".to_string(),
                summary: s.clone(),
                explanation: "Segment arrived with sequence number ahead of expected receive sequence. Common in multi-path routing or per-packet load balancing.".to_string(),
                recommended_action: "Verify ECMP (Equal-Cost Multi-Path) hashing algorithm is configured for 5-tuple flow pinning.".to_string(),
            });
        }

        // Flow Control & Zero Window Stalls
        if s.contains("ZeroWindow") || s.contains("[TCP ZeroWindow]") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Error,
                group: ExpertGroup::FlowControl,
                protocol: proto.clone(),
                title: "TCP Receive Window Exhaustion (Zero Window)".to_string(),
                summary: s.clone(),
                explanation: "Receiver set receive window size to 0 bytes. Target host application buffer is completely full and cannot accept incoming data.".to_string(),
                recommended_action: "Investigate target application CPU/RAM starvation and increase socket receive buffer sizes.".to_string(),
            });
        }

        // Connection State & Resets
        if has_token(s, "RST") || s.contains("connection reset") || s.contains("Connection reset") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Error,
                group: ExpertGroup::ProtocolViolation,
                protocol: proto.clone(),
                title: "Abrupt TCP Connection Reset (RST)".to_string(),
                summary: s.clone(),
                explanation: "Connection was abruptly terminated via TCP RST flag. Caused by closed target port, stateful firewall TCP timeout, or active Reset injection.".to_string(),
                recommended_action: "Verify target daemon status, firewall connection tracking tables, and potential active NDR/IPS reset injection.".to_string(),
            });
        }

        // DNS Failures
        if has_token(s, "SERVFAIL") || has_token(s, "NXDOMAIN") || has_token(s, "REFUSED") {
            diags.push(ProtocolDiagnosticInfo {
                severity: ExpertSeverity::Warning,
                group: ExpertGroup::General,
                protocol: proto.clone(),
                title: "DNS Resolution Error Response".to_string(),
                summary: s.clone(),
                explanation: "DNS authoritative server or resolver returned non-zero RCODE indicating domain lookup failure.".to_string(),
                recommended_action: "Check DNS resolver zone configuration, upstream DNS health, or domain typo-squatting.".to_string(),
            });
        }

        diags
    }

    /// Perform flow-level expert diagnostic analysis across multiple captured packets.
    pub fn analyze_flow(packets: &[Packet]) -> FlowExpertSummary {
        let total_packets = packets.len();
        let total_bytes: usize = packets.iter().map(|p| p.length).sum();

        if total_packets == 0 {
            return FlowExpertSummary {
                flow_key: "Empty Flow".to_string(),
                total_packets: 0,
                total_bytes: 0,
                health_score: 100.0,
                avg_rtt_ms: 0.0,
                packet_loss_rate_pct: 0.0,
                retransmission_count: 0,
                out_of_order_count: 0,
                zero_window_events: 0,
                diagnostics: vec![],
                severity_breakdown: BTreeMap::new(),
            };
        }

        let mut retransmissions = 0;
        let mut out_of_orders = 0;
        let mut zero_windows = 0;
        let mut all_diagnostics = Vec::new();
        let mut severity_map = BTreeMap::new();
        let mut rtt_samples = Vec::new();

        // Construct Flow Key from first packet
        let first_pkt = &packets[0];
        let src = first_pkt
            .src_addr
            .map_or("?".to_string(), |a| a.to_string());
        let dst = first_pkt
            .dst_addr
            .map_or("?".to_string(), |a| a.to_string());
        let flow_key = format!("{src} <-> {dst} ({})", first_pkt.protocol);

        for (i, p) in packets.iter().enumerate() {
            let diags = Self::analyze_packet(p);
            for d in &diags {
                *severity_map
                    .entry(d.severity.label().to_string())
                    .or_insert(0) += 1;
            }
            all_diagnostics.extend(diags);

            let s = &p.summary;
            if s.contains("[TCP Retransmission]") {
                retransmissions += 1;
            }
            if s.contains("[TCP Out-of-Order]") {
                out_of_orders += 1;
            }
            if s.contains("ZeroWindow") || s.contains("[TCP ZeroWindow]") {
                zero_windows += 1;
            }

            // Estimate RTT between SYN and SYN-ACK or request/response pair
            if i > 0 {
                let prev = &packets[i - 1];
                let dt = (p.timestamp - prev.timestamp)
                    .num_microseconds()
                    .unwrap_or(0) as f64
                    / 1000.0;
                if dt > 0.1 && dt < 5000.0 {
                    rtt_samples.push(dt);
                }
            }
        }

        let avg_rtt_ms = if rtt_samples.is_empty() {
            0.0
        } else {
            rtt_samples.iter().sum::<f64>() / rtt_samples.len() as f64
        };

        let loss_rate_pct = if total_packets > 0 {
            (retransmissions as f64 / total_packets as f64) * 100.0
        } else {
            0.0
        };

        // Calculate flow health score (100.0 = perfect, penalized by loss, resets, zero windows)
        let mut health = 100.0;
        health -= (loss_rate_pct * 5.0).min(50.0);
        health -= (out_of_orders as f64 * 3.0).min(20.0);
        health -= (zero_windows as f64 * 10.0).min(30.0);

        FlowExpertSummary {
            flow_key,
            total_packets,
            total_bytes,
            health_score: health.max(0.0),
            avg_rtt_ms,
            packet_loss_rate_pct: loss_rate_pct,
            retransmission_count: retransmissions,
            out_of_order_count: out_of_orders,
            zero_window_events: zero_windows,
            diagnostics: all_diagnostics,
            severity_breakdown: severity_map,
        }
    }
}

/// Whether `s` contains `token` as a whole word.
fn has_token(s: &str, token: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case(token))
}

/// Rank a packet the way Wireshark's expert info does.
pub fn classify(pkt: &Packet) -> ExpertSeverity {
    let s = &pkt.summary;

    if has_token(s, "RST")
        || s.contains("Malformed")
        || s.contains("unreachable")
        || s.contains("connection reset")
        || s.contains("Connection reset")
        || s.contains("bad checksum")
        || s.contains("Bad checksum")
        || s.contains("checksum mismatch")
        || s.contains("Threat detected")
        || s.contains("Alert triggered")
    {
        return ExpertSeverity::Error;
    }

    if s.contains("[TCP Retransmission]")
        || s.contains("[TCP Dup ACK")
        || s.contains("[TCP Out-of-Order]")
        || has_token(s, "SERVFAIL")
        || has_token(s, "NXDOMAIN")
        || has_token(s, "REFUSED")
    {
        return ExpertSeverity::Warning;
    }

    if s.contains("304 Not Modified")
        || s.contains("Connection opened")
        || s.contains("connection opened")
        || s.contains("Connection closing")
        || s.contains("connection closing")
        || has_token(s, "SYN")
        || has_token(s, "FIN")
    {
        return ExpertSeverity::Note;
    }

    ExpertSeverity::Chat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use bytes::Bytes;
    use chrono::Utc;

    fn pkt(summary: &str) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.10".parse().unwrap()),
            dst_addr: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 100,
            summary: summary.into(),
            data: Bytes::new(),
            llm: None,
        }
    }

    #[test]
    fn error_keywords() {
        assert_eq!(
            classify(&pkt("[RST] connection aborted")),
            ExpertSeverity::Error
        );
        assert_eq!(
            classify(&pkt("Connection reset by peer")),
            ExpertSeverity::Error
        );
        assert_eq!(classify(&pkt("Malformed packet")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("unreachable")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("bad checksum")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Threat detected")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Alert triggered")), ExpertSeverity::Error);
    }

    #[test]
    fn ordinary_traffic_is_not_mislabelled_by_substrings() {
        for summary in [
            "GET /api/SYNC HTTP/1.1",
            "HTTP/1.1 200 OK (1304 bytes)",
            "TCP 10.3.0.4:3040 -> 10.0.0.1:80",
            "GET /password-reset HTTP/1.1",
            "DNS query badminton-club.example",
            "GET /finance HTTP/1.1",
        ] {
            assert_eq!(
                classify(&pkt(summary)),
                ExpertSeverity::Chat,
                "{summary:?} was flagged by a bare substring match",
            );
        }
    }

    #[test]
    fn genuine_markers_still_classify() {
        assert_eq!(classify(&pkt("TCP [SYN] 1234 -> 80")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("TCP [FIN, ACK]")), ExpertSeverity::Note);
        assert_eq!(
            classify(&pkt("HTTP/1.1 304 Not Modified")),
            ExpertSeverity::Note
        );
    }

    #[test]
    fn warning_keywords() {
        assert_eq!(
            classify(&pkt("[TCP Retransmission]")),
            ExpertSeverity::Warning
        );
        assert_eq!(classify(&pkt("[TCP Dup ACK 42]")), ExpertSeverity::Warning);
        assert_eq!(
            classify(&pkt("[TCP Out-of-Order]")),
            ExpertSeverity::Warning
        );
        assert_eq!(classify(&pkt("SERVFAIL")), ExpertSeverity::Warning);
        assert_eq!(classify(&pkt("NXDOMAIN")), ExpertSeverity::Warning);
    }

    #[test]
    fn note_keywords() {
        assert_eq!(classify(&pkt("304 Not Modified")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("Connection opened")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("Connection closing")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("SYN")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("FIN")), ExpertSeverity::Note);
    }

    #[test]
    fn chat_is_the_fallback() {
        assert_eq!(classify(&pkt("normal packet")), ExpertSeverity::Chat);
        assert_eq!(classify(&pkt("")), ExpertSeverity::Chat);
    }

    #[test]
    fn label_roundtrip() {
        assert_eq!(ExpertSeverity::Chat.label(), "Chat");
        assert_eq!(ExpertSeverity::Note.label(), "Note");
        assert_eq!(ExpertSeverity::Warning.label(), "Warning");
        assert_eq!(ExpertSeverity::Error.label(), "Error");
    }

    #[test]
    fn test_senior_protocol_expert_engine() {
        let p1 = pkt("TCP [SYN] 50000 -> 80");
        let p2 = pkt("[TCP Retransmission] seq=100 len=1000");
        let p3 = pkt("TCP [ZeroWindow] win=0");
        let p4 = pkt("[RST] connection aborted");

        let diags = ProtocolExpertEngine::analyze_packet(&p2);
        assert!(!diags.is_empty());
        assert_eq!(diags[0].group, ExpertGroup::Sequence);

        let flow_summary = ProtocolExpertEngine::analyze_flow(&[p1, p2, p3, p4]);
        assert_eq!(flow_summary.total_packets, 4);
        assert_eq!(flow_summary.retransmission_count, 1);
        assert_eq!(flow_summary.zero_window_events, 1);
        assert!(flow_summary.health_score < 90.0);
    }
}
