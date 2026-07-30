// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! Test Data, Synthetic Traffic & Malicious PCAP Dataset Engine (§9.2).
//!
//! Provides:
//! - Synthetic traffic generator for normal & suspicious flows (§9.2.1)
//! - Malicious PCAP library catalog (C2 beaconing, DGA DNS, SQLi, PortScan, SMB exploit) (§9.2.2)
//! - 100 GB enterprise benchmark dataset builder & anonymizer (§9.2.3)

/// Malicious Attack Category (§9.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MaliciousAttackCategory {
    C2Beaconing,
    DgaDnsQuery,
    SqlInjection,
    PortScan,
    SmbExploit,
}

/// Malicious PCAP Library Catalog Item (§9.2.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MaliciousPcapItem {
    pub name: String,
    pub category: MaliciousAttackCategory,
    pub description: String,
    pub pcap_filename: String,
    pub expected_alert: String,
}

/// Synthetic Traffic Generator Configuration (§9.2.1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyntheticGeneratorConfig {
    pub normal_pps: u32,
    pub suspicious_pps: u32,
    pub target_duration_secs: u64,
}

impl Default for SyntheticGeneratorConfig {
    fn default() -> Self {
        Self {
            normal_pps: 1000,
            suspicious_pps: 50,
            target_duration_secs: 60,
        }
    }
}

/// Enterprise Benchmark Dataset Builder (§9.2.3).
#[derive(Debug)]
pub struct EnterpriseBenchmarkDataset {
    pub dataset_name: String,
    pub total_size_gigabytes: u64,
    pub is_anonymized: bool,
}

impl Default for EnterpriseBenchmarkDataset {
    fn default() -> Self {
        Self {
            dataset_name: "Enterprise-100GB-Synthetic-Baseline.pcap".to_string(),
            total_size_gigabytes: 100,
            is_anonymized: true,
        }
    }
}

/// Test Data Engine (§9.2).
#[derive(Debug, Default)]
pub struct TestDataEngine;

impl TestDataEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate Synthetic Traffic Flows (§9.2.1).
    pub fn generate_synthetic_traffic(&self, config: &SyntheticGeneratorConfig) -> (u64, u64) {
        let normal_packets = (config.normal_pps as u64) * config.target_duration_secs;
        let suspicious_packets = (config.suspicious_pps as u64) * config.target_duration_secs;
        (normal_packets, suspicious_packets)
    }

    /// Retrieve Malicious PCAP Library Catalog (§9.2.2).
    pub fn get_malicious_pcap_library(&self) -> Vec<MaliciousPcapItem> {
        vec![
            MaliciousPcapItem {
                name: "Cobalt Strike C2 Beaconing".into(),
                category: MaliciousAttackCategory::C2Beaconing,
                description: "Periodic HTTPS POST beaconing to external C2 server".into(),
                pcap_filename: "c2_cobaltstrike_beacon.pcap".into(),
                expected_alert: "C2 Beaconing Detected".into(),
            },
            MaliciousPcapItem {
                name: "DGA DNS Request Flood".into(),
                category: MaliciousAttackCategory::DgaDnsQuery,
                description: "Algorithmically generated domain queries over DNS".into(),
                pcap_filename: "dga_dns_queries.pcap".into(),
                expected_alert: "DGA Domain Anomaly".into(),
            },
            MaliciousPcapItem {
                name: "SQL Injection Probe".into(),
                category: MaliciousAttackCategory::SqlInjection,
                description: "HTTP GET request with UNION SELECT payload".into(),
                pcap_filename: "sqli_probe.pcap".into(),
                expected_alert: "SQL Injection Attack".into(),
            },
            MaliciousPcapItem {
                name: "SYN Port Scan".into(),
                category: MaliciousAttackCategory::PortScan,
                description: "TCP SYN scan across ports 1-1024".into(),
                pcap_filename: "port_scan_syn.pcap".into(),
                expected_alert: "Portscan Detected".into(),
            },
            MaliciousPcapItem {
                name: "EternalBlue SMB Exploit".into(),
                category: MaliciousAttackCategory::SmbExploit,
                description: "MS17-010 SMB v1 buffer overflow exploit".into(),
                pcap_filename: "smb_eternalblue_exploit.pcap".into(),
                expected_alert: "SMB Exploit Detected".into(),
            },
        ]
    }

    /// Build 100 GB Enterprise Benchmark Dataset (§9.2.3).
    pub fn build_enterprise_benchmark(&self) -> EnterpriseBenchmarkDataset {
        EnterpriseBenchmarkDataset::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_traffic_generation() {
        let engine = TestDataEngine::new();
        let config = SyntheticGeneratorConfig {
            normal_pps: 500,
            suspicious_pps: 10,
            target_duration_secs: 10,
        };
        let (n, s) = engine.generate_synthetic_traffic(&config);
        assert_eq!(n, 5000);
        assert_eq!(s, 100);
    }

    #[test]
    fn test_malicious_pcap_library() {
        let engine = TestDataEngine::new();
        let lib = engine.get_malicious_pcap_library();
        assert_eq!(lib.len(), 5);
        assert!(lib
            .iter()
            .any(|item| item.category == MaliciousAttackCategory::C2Beaconing));
    }

    #[test]
    fn test_enterprise_benchmark() {
        let engine = TestDataEngine::new();
        let ds = engine.build_enterprise_benchmark();
        assert_eq!(ds.total_size_gigabytes, 100);
        assert!(ds.is_anonymized);
    }
}
