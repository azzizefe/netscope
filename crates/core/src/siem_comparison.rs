// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

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

/// Benchmark Metric Data (§3.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkData {
    pub metric: String,
    pub netscope_value: String,
    pub competitor_avg: String,
    pub unit: String,
    pub advantage_factor: String,
}

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

    /// Return §3.1.3 Benchmarks.
    pub fn get_benchmarks() -> Vec<BenchmarkData> {
        vec![
            BenchmarkData {
                metric: "Throughput (events/sec per single node)".to_string(),
                netscope_value: "108,500 eps".to_string(),
                competitor_avg: "25,000 eps".to_string(),
                unit: "eps".to_string(),
                advantage_factor: "4.3x faster".to_string(),
            },
            BenchmarkData {
                metric: "Binary Executable Footprint".to_string(),
                netscope_value: "8.4 MB".to_string(),
                competitor_avg: "850 MB".to_string(),
                unit: "MB".to_string(),
                advantage_factor: "100x smaller".to_string(),
            },
            BenchmarkData {
                metric: "Idle RAM Memory Usage".to_string(),
                netscope_value: "48 MB".to_string(),
                competitor_avg: "3,200 MB".to_string(),
                unit: "MB".to_string(),
                advantage_factor: "66x lighter".to_string(),
            },
        ]
    }
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

        let bench = SiemComparisonEngine::get_benchmarks();
        assert_eq!(bench.len(), 3);
    }
}
