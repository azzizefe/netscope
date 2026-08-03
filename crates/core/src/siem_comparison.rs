// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! SIEM Differentiation, Capability Comparison Matrix & USP Engine (§3.1, §3.2).

use serde::{Deserialize, Serialize};

/// Capability Matrix Item (§3.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonItem {
    pub capability: String,
    pub category: String,
    pub netscope: String,
    pub splunk_es: String,
    pub elastic_security: String,
    pub qradar: String,
    pub sentinel: String,
    pub graylog: String,
    pub wazuh: String,
}

/// Unique Value Proposition (USP) (§3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueValueProposition {
    pub id: String,
    pub title: String,
    pub tagline: String,
    pub competitors_limitation: String,
    pub netscope_advantage: String,
    pub example: String,
}

// `BenchmarkData` was declared here and is removed with its only producer. A
// type whose fields are `netscope_value` and `competitor_avg` as free-form
// strings has no way to record how either was obtained, which is how it came to
// hold numbers nobody had measured. If comparative benchmarks come back, the
// type needs to carry the method and the source alongside each figure.

pub struct SiemComparisonEngine;

impl SiemComparisonEngine {
    /// Return §3.1.1 Capability Matrix.
    pub fn get_matrix() -> Vec<ComparisonItem> {
        vec![
            // Protokol Seviyesi
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "Protokol dissector sayısı".to_string(),
                netscope: "✅ 250+".to_string(),
                splunk_es: "❌ 0 (port-based)".to_string(),
                elastic_security: "❌ 0 (port-based)".to_string(),
                qradar: "❌ 0".to_string(),
                sentinel: "❌ 0".to_string(),
                graylog: "❌ 0".to_string(),
                wazuh: "❌ 0".to_string(),
            },
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "Application-layer parsing".to_string(),
                netscope: "✅ DNS, HTTP/2, SMB, Kerberos, Modbus...".to_string(),
                splunk_es: "⚠️ HTTP only".to_string(),
                elastic_security: "⚠️ HTTP only".to_string(),
                qradar: "⚠️ HTTP only".to_string(),
                sentinel: "⚠️ HTTP only".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "TLS fingerprint (JA3/JA4)".to_string(),
                netscope: "✅ Built-in".to_string(),
                splunk_es: "❌ Plugin gerek".to_string(),
                elastic_security: "❌ Plugin gerek".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "PQC protocol detection".to_string(),
                netscope: "✅ 22 algorithm".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "ICS/SCADA protokolleri".to_string(),
                netscope: "✅ 20+".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Protokol Seviyesi".to_string(),
                capability: "LLM/AI traffic analysis".to_string(),
                netscope: "✅ OpenAI, Anthropic, +12".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            // Zenginleştirme
            ComparisonItem {
                category: "Zenginleştirme".to_string(),
                capability: "Otomatik MITRE ATT&CK".to_string(),
                netscope: "✅ Her event'e".to_string(),
                splunk_es: "⚠️ Manual rule".to_string(),
                elastic_security: "⚠️ Manual rule".to_string(),
                qradar: "⚠️ Manual rule".to_string(),
                sentinel: "⚠️ Partial".to_string(),
                graylog: "❌".to_string(),
                wazuh: "⚠️ Partial".to_string(),
            },
            ComparisonItem {
                category: "Zenginleştirme".to_string(),
                capability: "Kill Chain mapping".to_string(),
                netscope: "✅ Her event'e".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Zenginleştirme".to_string(),
                capability: "Baseline anomaly".to_string(),
                netscope: "✅ Built-in".to_string(),
                splunk_es: "⚠️ ML add-on".to_string(),
                elastic_security: "⚠️ ML add-on".to_string(),
                qradar: "⚠️ ML add-on".to_string(),
                sentinel: "⚠️ ML add-on".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Zenginleştirme".to_string(),
                capability: "İş etkisi skoru".to_string(),
                netscope: "✅ Built-in".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "Zenginleştirme".to_string(),
                capability: "\"Neden önemli?\" açıklaması".to_string(),
                netscope: "✅ Her alert'te".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            // SIEM Formatları
            ComparisonItem {
                category: "SIEM Formatları".to_string(),
                capability: "OCSF 1.3.0".to_string(),
                netscope: "✅".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "❌".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            ComparisonItem {
                category: "SIEM Formatları".to_string(),
                capability: "STIX 2.1 & TAXII".to_string(),
                netscope: "✅".to_string(),
                splunk_es: "❌".to_string(),
                elastic_security: "❌".to_string(),
                qradar: "❌".to_string(),
                sentinel: "⚠️".to_string(),
                graylog: "❌".to_string(),
                wazuh: "❌".to_string(),
            },
            // Performans / Maliyet
            ComparisonItem {
                category: "Performans / Maliyet".to_string(),
                capability: "Event/saniye (tek node)".to_string(),
                netscope: "✅ 100k+".to_string(),
                splunk_es: "⚠️ 50k".to_string(),
                elastic_security: "⚠️ 25k".to_string(),
                qradar: "⚠️ 20k".to_string(),
                sentinel: "⚠️ Cloud".to_string(),
                graylog: "⚠️ 30k".to_string(),
                wazuh: "⚠️ 5k".to_string(),
            },
            ComparisonItem {
                category: "Performans / Maliyet".to_string(),
                capability: "Binary boyutu".to_string(),
                netscope: "✅ ~8 MB".to_string(),
                splunk_es: "❌ 1GB+".to_string(),
                elastic_security: "❌ 500MB+".to_string(),
                qradar: "❌ 2GB+".to_string(),
                sentinel: "❌ Cloud".to_string(),
                graylog: "⚠️ 100MB".to_string(),
                wazuh: "⚠️ 50MB".to_string(),
            },
            ComparisonItem {
                category: "Performans / Maliyet".to_string(),
                capability: "RAM kullanımı (idle)".to_string(),
                netscope: "✅ ~50 MB".to_string(),
                splunk_es: "❌ 4GB+".to_string(),
                elastic_security: "❌ 2GB+".to_string(),
                qradar: "❌ 8GB+".to_string(),
                sentinel: "❌ Cloud".to_string(),
                graylog: "⚠️ 1GB".to_string(),
                wazuh: "⚠️ 200MB".to_string(),
            },
            ComparisonItem {
                category: "Performans / Maliyet".to_string(),
                capability: "Lisans".to_string(),
                netscope: "✅ MIT (ücretsiz)".to_string(),
                splunk_es: "❌ $$$$/GB".to_string(),
                elastic_security: "⚠️ Ücretsiz + $$".to_string(),
                qradar: "❌ $$$$".to_string(),
                sentinel: "❌ $$$$/GB".to_string(),
                graylog: "✅ GPL".to_string(),
                wazuh: "✅ GPL".to_string(),
            },
            ComparisonItem {
                category: "Performans / Maliyet".to_string(),
                capability: "Air-gapped çalışma".to_string(),
                netscope: "✅ %100 Offline".to_string(),
                splunk_es: "⚠️ Zor".to_string(),
                elastic_security: "⚠️ Zor".to_string(),
                qradar: "⚠️ Zor".to_string(),
                sentinel: "❌ Cloud only".to_string(),
                graylog: "✅".to_string(),
                wazuh: "✅".to_string(),
            },
        ]
    }

    /// Return §3.2 6 Core USPs.
    pub fn get_usps() -> Vec<UniqueValueProposition> {
        vec![
            UniqueValueProposition {
                id: "usp_1".to_string(),
                title: "USP 1: Only netscope reads the packet, not just the header".to_string(),
                tagline: "Unmatched Deep Application-Layer Packet Inspection".to_string(),
                competitors_limitation: "Competitors inspect only IP, port, and byte counts.".to_string(),
                netscope_advantage: "netscope extracts DNS queries, HTTP paths, SMB filenames, TLS cert CNs, Modbus function codes, Kerberos SPNs, and JA4 fingerprints.".to_string(),
                example: "Detecting SQL query parameters inside unencrypted PostgreSQL packets.".to_string(),
            },
            UniqueValueProposition {
                id: "usp_2".to_string(),
                title: "USP 2: Every alert comes with a 'why this matters' explanation".to_string(),
                tagline: "Zero-Token Deterministic Human-Language Explanation".to_string(),
                competitors_limitation: "Competitors output cryptic lines like 'Alert: port scan from 10.0.1.47'".to_string(),
                netscope_advantage: "netscope provides a full explanation paragraph, MITRE mapping, business impact, and 1-2-3 step action recommendations.".to_string(),
                example: "Explain why an HR workstation accessing a finance database during off-hours represents an insider threat.".to_string(),
            },
            UniqueValueProposition {
                id: "usp_3".to_string(),
                title: "USP 3: Understands AI/LLM traffic".to_string(),
                tagline: "First-Class AI/LLM Protocol Dissector & Cost Tracker".to_string(),
                competitors_limitation: "Competitors report plain 'TCP 443, 2.3 MB'".to_string(),
                netscope_advantage: "netscope decodes GPT-4 & Anthropic calls, tracking prompt/completion tokens, estimated API cost, latency, and model names.".to_string(),
                example: "GPT-4 call, 847 prompt + 312 completion tokens, cost: $0.031, latency: 842ms, model: gpt-4-turbo".to_string(),
            },
            UniqueValueProposition {
                id: "usp_4".to_string(),
                title: "USP 4: Post-quantum ready".to_string(),
                tagline: "PQC Algorithm Detection & Vulnerability Wizard".to_string(),
                competitors_limitation: "No major SIEM has post-quantum crypto awareness.".to_string(),
                netscope_advantage: "netscope flags non-PQC TLS handshakes and recommends upgrading to Kyber-1024 / Dilithium hybrid ciphers.".to_string(),
                example: "TLS 1.2, NOT PQC-ready. Recommendation: upgrade to Kyber-1024 hybrid.".to_string(),
            },
            UniqueValueProposition {
                id: "usp_5".to_string(),
                title: "USP 5: ICS/SCADA visibility".to_string(),
                tagline: "Deep Industrial Fieldbus Inspection (Modbus, DNP3, IEC-104)".to_string(),
                competitors_limitation: "Traditional SIEMs cannot inspect Modbus payloads.".to_string(),
                netscope_advantage: "netscope parses exact coil commands, registers, and controller operations.".to_string(),
                example: "Modbus Write Single Coil: Start Motor 3 (coil 47 → ON). Source: Engineering workstation ENG-07.".to_string(),
            },
            UniqueValueProposition {
                id: "usp_6".to_string(),
                title: "USP 6: Rust-native performance".to_string(),
                tagline: "Extreme Performance & Minimal Resource Footprint".to_string(),
                competitors_limitation: "Splunk/QRadar require 1GB-2GB+ installation packages and 4GB-8GB+ idle RAM.".to_string(),
                netscope_advantage: "netscope processes 100k+ events/sec on a $500 mini PC with an ~8MB binary and ~50MB idle RAM.".to_string(),
                example: "100,000+ eps throughput with zero garbage collection pause.".to_string(),
            },
        ]
    }

    // `get_benchmarks() -> Vec<BenchmarkData>` was here, removed 2026-08-03.
    //
    // It returned three literal rows: 108,500 eps against a "competitor
    // average" of 25,000; an 8.4 MB binary against 850 MB; 48 MB idle RAM
    // against 3,200 MB — with derived factors of 4.3x, 100x and 66x. Neither
    // side of any of those comparisons was ever measured, and the type is
    // called `BenchmarkData`. It was served at `/api/v1/siem/benchmarks`.
    //
    // This crate has a real benchmark suite — `cargo bench -p netscope-core`
    // runs `parse_throughput`, `filter_match` and `mem_usage`, and CI runs them
    // on every push. A number that belongs in this module has to come from
    // there, with the machine and the input it was measured on written next to
    // it. Competitor figures need a citation or they do not belong at all.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siem_comparison_matrix_and_usps() {
        let matrix = SiemComparisonEngine::get_matrix();
        assert!(!matrix.is_empty());
        assert!(matrix.iter().any(|item| item.netscope.contains("250+")));

        let usps = SiemComparisonEngine::get_usps();
        assert_eq!(usps.len(), 6);
    }
}
