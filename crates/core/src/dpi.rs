// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Deep Packet Inspection (DPI) Engine
//!
//! Provides deep layer-by-layer packet disassembly, payload classification,
//! Shannon entropy calculation, side-by-side Hex/ASCII dump formatting,
//! printable string extraction, protocol field tree generation, and deep
//! security/anomaly finding detection.

use serde::{Deserialize, Serialize};

use crate::models::{Packet, Protocol};

/// Payload classification type identified by DPI analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpiPayloadType {
    Text,
    Json,
    SseStream,
    Binary,
    Encrypted,
    Compressed,
    Executable,
    Empty,
    Unknown,
}

impl std::fmt::Display for DpiPayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpiPayloadType::Text => write!(f, "ASCII/UTF-8 Plain Text"),
            DpiPayloadType::Json => write!(f, "JSON Document"),
            DpiPayloadType::SseStream => write!(f, "Server-Sent Events (SSE) Stream"),
            DpiPayloadType::Binary => write!(f, "Raw Binary Payload"),
            DpiPayloadType::Encrypted => write!(f, "High-Entropy Encrypted Data"),
            DpiPayloadType::Compressed => write!(f, "Compressed Data Stream"),
            DpiPayloadType::Executable => write!(f, "Executable / ELF / PE Header"),
            DpiPayloadType::Empty => write!(f, "Empty Payload"),
            DpiPayloadType::Unknown => write!(f, "Unclassified Payload"),
        }
    }
}

/// A node in the protocol field hierarchy tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiField {
    pub name: String,
    pub value: String,
    pub offset: usize,
    pub length: usize,
    pub children: Vec<DpiField>,
}

/// Security or protocol finding detected during deep packet inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiFinding {
    pub severity: String, // "informational", "low", "medium", "high", "critical"
    pub category: String, // "anomaly", "signature", "entropy", "malformed", "credentials", "injection"
    pub title: String,
    pub description: String,
}

/// Complete result of a Deep Packet Inspection operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiAnalysisResult {
    pub packet_summary: String,
    pub protocol: String,
    pub protocol_stack: Vec<String>,
    pub payload_type: DpiPayloadType,
    pub payload_bytes: usize,
    pub entropy_score: f64,
    pub hex_dump: String,
    pub extracted_strings: Vec<String>,
    pub field_tree: Vec<DpiField>,
    pub findings: Vec<DpiFinding>,
}

/// Deep Packet Inspection Engine.
pub struct DpiEngine;

impl DpiEngine {
    /// Perform full deep packet inspection on a packet.
    pub fn inspect(packet: &Packet) -> DpiAnalysisResult {
        let payload = &packet.data;
        let entropy_score = Self::calculate_entropy(payload);
        let payload_type = Self::classify_payload(payload, &packet.protocol, entropy_score);
        let hex_dump = Self::format_hex_ascii_dump(payload, 32);
        let extracted_strings = Self::extract_strings(payload, 4);
        let protocol_stack = Self::build_protocol_stack(packet);
        let field_tree = Self::build_field_tree(packet, &payload_type, entropy_score);
        let findings = Self::detect_findings(packet, payload, &payload_type, entropy_score);

        DpiAnalysisResult {
            packet_summary: packet.summary.clone(),
            protocol: packet.protocol.to_string(),
            protocol_stack,
            payload_type,
            payload_bytes: payload.len(),
            entropy_score,
            hex_dump,
            extracted_strings,
            field_tree,
            findings,
        }
    }

    /// Calculate Shannon entropy (bits per byte, 0.0 to 8.0).
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Format payload as side-by-side Hex and ASCII dump.
    pub fn format_hex_ascii_dump(data: &[u8], max_lines: usize) -> String {
        if data.is_empty() {
            return "[Empty Payload]".to_string();
        }
        let mut out = String::new();
        let bytes_per_line = 16;
        let max_bytes = max_lines * bytes_per_line;
        let data_to_show = if data.len() > max_bytes {
            &data[..max_bytes]
        } else {
            data
        };

        for (i, chunk) in data_to_show.chunks(bytes_per_line).enumerate() {
            let offset = i * bytes_per_line;
            out.push_str(&format!("{offset:08x}  "));

            // Hex representation
            for (j, &b) in chunk.iter().enumerate() {
                out.push_str(&format!("{b:02x} "));
                if j == 7 {
                    out.push(' ');
                }
            }

            // Padding for short lines
            if chunk.len() < bytes_per_line {
                let missing = bytes_per_line - chunk.len();
                for j in 0..missing {
                    out.push_str("   ");
                    if chunk.len() + j == 7 {
                        out.push(' ');
                    }
                }
            }

            out.push_str(" |");
            // ASCII representation
            for &b in chunk {
                if b.is_ascii_graphic() || b == b' ' {
                    out.push(b as char);
                } else {
                    out.push('.');
                }
            }
            out.push_str("|\n");
        }

        if data.len() > max_bytes {
            out.push_str(&format!(
                "... [{} bytes omitted, total payload size: {} B]\n",
                data.len() - max_bytes,
                data.len()
            ));
        }

        out
    }

    /// Extract printable ASCII / UTF-8 string sequences of length >= min_len.
    pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current = Vec::new();

        for &b in data {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                current.push(b);
            } else {
                if current.len() >= min_len {
                    if let Ok(s) = String::from_utf8(current.clone()) {
                        strings.push(s.trim().to_string());
                    }
                }
                current.clear();
            }
        }
        if current.len() >= min_len {
            if let Ok(s) = String::from_utf8(current) {
                strings.push(s.trim().to_string());
            }
        }

        strings.into_iter().filter(|s| !s.is_empty()).collect()
    }

    /// Classify payload type using heuristic signatures and entropy.
    pub fn classify_payload(data: &[u8], _protocol: &Protocol, entropy: f64) -> DpiPayloadType {
        if data.is_empty() {
            return DpiPayloadType::Empty;
        }

        // Executable magic bytes
        if data.len() >= 4 && (&data[..2] == b"MZ" || &data[..4] == b"\x7fELF") {
            return DpiPayloadType::Executable;
        }

        // SSE Stream
        if data.starts_with(b"data: ") || data.contains_str("event: ") {
            return DpiPayloadType::SseStream;
        }

        // JSON Document
        let trimmed = data.trim_ascii_whitespace();
        if (trimmed.starts_with(b"{") && trimmed.ends_with(b"}"))
            || (trimmed.starts_with(b"[") && trimmed.ends_with(b"]"))
        {
            return DpiPayloadType::Json;
        }

        // High entropy encrypted data
        if entropy > 7.4 {
            return DpiPayloadType::Encrypted;
        }

        // Compressed signatures (gzip, zlib, zip)
        if data.len() >= 2 && (data.starts_with(b"\x1f\x8b") || data.starts_with(b"PK")) {
            return DpiPayloadType::Compressed;
        }

        // Plain text vs Binary
        let printable_count = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        let printable_ratio = printable_count as f64 / data.len() as f64;

        if printable_ratio > 0.85 {
            DpiPayloadType::Text
        } else {
            DpiPayloadType::Binary
        }
    }

    /// Build L2 -> L7 protocol stack hierarchy.
    pub fn build_protocol_stack(packet: &Packet) -> Vec<String> {
        let mut stack = vec!["Ethernet (L2)".to_string()];
        if packet.src_addr.is_some_and(|a| a.is_ipv6()) {
            stack.push("IPv6 (L3)".to_string());
        } else {
            stack.push("IPv4 (L3)".to_string());
        }

        if packet.src_port.is_some() || packet.dst_port.is_some() {
            let port = packet.src_port.or(packet.dst_port).unwrap_or(0);
            if port == 53 || port == 5353 {
                stack.push("UDP (L4)".to_string());
            } else {
                stack.push("TCP (L4)".to_string());
            }
        }

        stack.push(format!("{} (L7)", packet.protocol));
        stack
    }

    /// Build hierarchical protocol field inspection tree.
    pub fn build_field_tree(
        packet: &Packet,
        payload_type: &DpiPayloadType,
        entropy: f64,
    ) -> Vec<DpiField> {
        let mut tree = Vec::new();

        // L3 IP Layer
        let mut ip_fields = Vec::new();
        if let Some(src) = packet.src_addr {
            ip_fields.push(DpiField {
                name: "Source IP".to_string(),
                value: src.to_string(),
                offset: 12,
                length: 4,
                children: vec![],
            });
        }
        if let Some(dst) = packet.dst_addr {
            ip_fields.push(DpiField {
                name: "Destination IP".to_string(),
                value: dst.to_string(),
                offset: 16,
                length: 4,
                children: vec![],
            });
        }
        tree.push(DpiField {
            name: "Internet Protocol (L3)".to_string(),
            value: format!("Length: {} bytes", packet.length),
            offset: 0,
            length: 20,
            children: ip_fields,
        });

        // L4 Transport Layer
        let mut l4_fields = Vec::new();
        if let Some(sp) = packet.src_port {
            l4_fields.push(DpiField {
                name: "Source Port".to_string(),
                value: sp.to_string(),
                offset: 20,
                length: 2,
                children: vec![],
            });
        }
        if let Some(dp) = packet.dst_port {
            l4_fields.push(DpiField {
                name: "Destination Port".to_string(),
                value: dp.to_string(),
                offset: 22,
                length: 2,
                children: vec![],
            });
        }
        tree.push(DpiField {
            name: "Transport Layer (L4)".to_string(),
            value: packet.summary.clone(),
            offset: 20,
            length: 20,
            children: l4_fields,
        });

        // L7 Application Payload
        let mut l7_fields = Vec::new();
        l7_fields.push(DpiField {
            name: "Payload Type".to_string(),
            value: payload_type.to_string(),
            offset: 40,
            length: packet.data.len(),
            children: vec![],
        });
        l7_fields.push(DpiField {
            name: "Shannon Entropy".to_string(),
            value: format!("{entropy:.4} bits/byte"),
            offset: 40,
            length: packet.data.len(),
            children: vec![],
        });

        if let Some(ref llm) = packet.llm {
            l7_fields.push(DpiField {
                name: "LLM Provider".to_string(),
                value: llm.provider.clone(),
                offset: 40,
                length: 0,
                children: vec![],
            });
            l7_fields.push(DpiField {
                name: "LLM Model".to_string(),
                value: llm.model.clone(),
                offset: 40,
                length: 0,
                children: vec![],
            });
            if let Some(cost) = llm.cost_usd {
                l7_fields.push(DpiField {
                    name: "Estimated Cost".to_string(),
                    value: format!("${cost:.6}"),
                    offset: 40,
                    length: 0,
                    children: vec![],
                });
            }
        }

        tree.push(DpiField {
            name: format!("Application Layer - {}", packet.protocol),
            value: format!("Payload: {} bytes", packet.data.len()),
            offset: 40,
            length: packet.data.len(),
            children: l7_fields,
        });

        tree
    }

    /// Detect deep security findings, protocol violations, or payload anomalies.
    pub fn detect_findings(
        _packet: &Packet,
        payload: &[u8],
        payload_type: &DpiPayloadType,
        entropy: f64,
    ) -> Vec<DpiFinding> {
        let mut findings = Vec::new();

        // High entropy finding (suspected encryption/steganography/exfiltration)
        if entropy > 7.7 && payload.len() > 64 {
            findings.push(DpiFinding {
                severity: "medium".to_string(),
                category: "entropy".to_string(),
                title: "High Entropy Payload Detected".to_string(),
                description: format!(
                    "Payload entropy is {:.2} bits/byte (near-maximum random/encrypted). Potential obfuscated or encrypted tunnel payload.",
                    entropy
                ),
            });
        }

        // Executable payload in network traffic
        if *payload_type == DpiPayloadType::Executable {
            findings.push(DpiFinding {
                severity: "high".to_string(),
                category: "security".to_string(),
                title: "Executable Binary Header In Network Payload".to_string(),
                description: "Payload starts with PE (MZ) or ELF executable magic bytes. Potential binary executable download or malware transfer.".to_string(),
            });
        }

        // Cleartext sensitive keywords (SQL injection, credential leak, path traversal)
        let s = String::from_utf8_lossy(payload).to_lowercase();
        if s.contains("union select") || s.contains("or 1=1") || s.contains("<script>") {
            findings.push(DpiFinding {
                severity: "high".to_string(),
                category: "injection".to_string(),
                title: "Suspected Web Injection Attack Payload".to_string(),
                description: "DPI engine matched SQL injection or Cross-Site Scripting (XSS) pattern in request payload.".to_string(),
            });
        }
        if s.contains("../..") || s.contains("/etc/passwd") || s.contains("c:\\windows\\system32") {
            findings.push(DpiFinding {
                severity: "high".to_string(),
                category: "injection".to_string(),
                title: "Path Traversal Payload Detected".to_string(),
                description: "Directory traversal sequences (../ or system paths) detected in packet payload.".to_string(),
            });
        }
        if s.contains("password=") || s.contains("api_key=") || s.contains("bearer ey") {
            findings.push(DpiFinding {
                severity: "medium".to_string(),
                category: "credentials".to_string(),
                title: "Unencrypted Credential / Token In Payload".to_string(),
                description: "Cleartext credentials or API tokens detected in unencrypted packet payload.".to_string(),
            });
        }

        findings
    }
}

trait ByteSliceExt {
    fn contains_str(&self, needle: &str) -> bool;
    fn trim_ascii_whitespace(&self) -> &[u8];
}

impl ByteSliceExt for [u8] {
    fn contains_str(&self, needle: &str) -> bool {
        self.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    fn trim_ascii_whitespace(&self) -> &[u8] {
        let start = self
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        let end = self
            .iter()
            .rposition(|&b| !b.is_ascii_whitespace())
            .map(|i| i + 1)
            .unwrap_or(self.len());
        if start >= end {
            &[]
        } else {
            &self[start..end]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;

    #[test]
    fn test_shannon_entropy() {
        let zeroes = vec![0u8; 100];
        assert_eq!(DpiEngine::calculate_entropy(&zeroes), 0.0);

        let ascii = b"Hello World! This is plain text.";
        let e_ascii = DpiEngine::calculate_entropy(ascii);
        assert!(e_ascii > 3.0 && e_ascii < 5.0);
    }

    #[test]
    fn test_format_hex_ascii_dump() {
        let data = b"NETSCOPE DPI ENGINE";
        let dump = DpiEngine::format_hex_ascii_dump(data, 10);
        assert!(dump.contains("4e 45 54 53 43 4f 50 45"));
        assert!(dump.contains("|NETSCOPE DPI ENG|"));
    }

    #[test]
    fn test_extract_strings() {
        let data = b"\x00\x00\x00ADMIN_USER\x00\x00PASS_1234\x00";
        let extracted = DpiEngine::extract_strings(data, 4);
        assert_eq!(extracted, vec!["ADMIN_USER", "PASS_1234"]);
    }

    #[test]
    fn test_payload_classification_json() {
        let json_payload = b"{\"model\": \"gpt-4o\", \"prompt\": \"hello\"}";
        let ptype = DpiEngine::classify_payload(json_payload, &Protocol::OpenaiChatStream, 4.0);
        assert_eq!(ptype, DpiPayloadType::Json);
    }

    #[test]
    fn test_dpi_findings_injection() {
        let packet = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.100".parse().unwrap()),
            dst_addr: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 120,
            summary: "GET /query?id=1 OR 1=1 HTTP/1.1".to_string(),
            data: Bytes::from_static(b"GET /query?id=1 UNION SELECT * FROM users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            llm: None,
        };
        let res = DpiEngine::inspect(&packet);
        assert!(res.findings.iter().any(|f| f.category == "injection"));
    }
}
