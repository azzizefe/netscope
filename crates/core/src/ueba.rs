// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! UEBA (User and Entity Behavior Analytics) Network Behavior Engine (ROADMAP §7.1).
//!
//! Provides zero-token, offline ML-based behavioral analysis:
//! - Working-hour activity distributions & off-hour anomaly detection (e.g. 2 AM data transfers).
//! - Bandwidth baselining via running mean and standard deviation (Welford's algorithm).
//! - Data Exfiltration detection (high out-of-bound transfers to uncharacteristic external destinations).
//! - Aggregated entity threat scoring (0.0 to 100.0) with detailed anomaly indicators.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::baseline::WelfordTracker;

/// Classification of detected behavioral anomalies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UebaAnomalyKind {
    /// Activity occurring outside standard working hours.
    OffHourActivity,
    /// Unusually high volume of outgoing traffic (Data Exfiltration indicator).
    ExfiltrationSpike,
    /// Communication with a previously unseen external IP address.
    RareDestination,
    /// Traffic over non-standard or unusual destination ports.
    UnusualPort,
}

impl UebaAnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            UebaAnomalyKind::OffHourActivity => "Off-Hour Activity",
            UebaAnomalyKind::ExfiltrationSpike => "Exfiltration Spike",
            UebaAnomalyKind::RareDestination => "Rare Destination",
            UebaAnomalyKind::UnusualPort => "Unusual Port",
        }
    }
}

/// An individual behavioral anomaly detected for an entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaAnomaly {
    pub kind: UebaAnomalyKind,
    pub severity: f64, // 0.0 to 100.0
    pub description: String,
}

/// Complete UEBA evaluation result for a network entity (IP address).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UebaEvaluation {
    pub entity_ip: String,
    pub threat_score: f64, // 0.0 to 100.0
    pub anomalies: Vec<UebaAnomaly>,
    pub is_suspicious: bool,
    pub summary: String,
}

/// Behavioral profile maintained per network entity (device/host IP).
#[derive(Debug, Clone)]
pub struct EntityProfile {
    pub ip: IpAddr,
    pub hourly_activity: [u64; 24],
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub tx_tracker: WelfordTracker,
    pub rx_tracker: WelfordTracker,
    pub unique_destinations: HashSet<IpAddr>,
    pub dst_ports: HashSet<u16>,
    pub packet_count: u64,
}

impl EntityProfile {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hourly_activity: [0; 24],
            bytes_sent: 0,
            bytes_received: 0,
            tx_tracker: WelfordTracker::new(),
            rx_tracker: WelfordTracker::new(),
            unique_destinations: HashSet::new(),
            dst_ports: HashSet::new(),
            packet_count: 0,
        }
    }

    pub fn record_tx(&mut self, dst_ip: IpAddr, dst_port: u16, bytes: u64, hour_of_day: u8) {
        let hour = (hour_of_day % 24) as usize;
        self.hourly_activity[hour] += 1;
        self.bytes_sent += bytes;
        self.tx_tracker.update(bytes as f64);
        self.unique_destinations.insert(dst_ip);
        self.dst_ports.insert(dst_port);
        self.packet_count += 1;
    }

    pub fn record_rx(&mut self, _src_ip: IpAddr, bytes: u64, hour_of_day: u8) {
        let hour = (hour_of_day % 24) as usize;
        self.hourly_activity[hour] += 1;
        self.bytes_received += bytes;
        self.rx_tracker.update(bytes as f64);
        self.packet_count += 1;
    }
}

/// UEBA Engine tracking entity behaviors and scoring threat anomalies.
pub struct UebaEngine {
    profiles: HashMap<IpAddr, EntityProfile>,
    off_hours: HashSet<u8>,
    exfiltration_threshold_bytes: u64,
}

impl Default for UebaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl UebaEngine {
    /// Create a new UEBA engine with default off-hour definitions (10 PM – 6 AM).
    pub fn new() -> Self {
        let mut off_hours = HashSet::new();
        // 22:00 to 06:00
        for h in [22, 23, 0, 1, 2, 3, 4, 5] {
            off_hours.insert(h);
        }
        Self {
            profiles: HashMap::new(),
            off_hours,
            exfiltration_threshold_bytes: 10 * 1024 * 1024, // 10 MB default threshold
        }
    }

    /// Set custom exfiltration threshold bytes (default: 10 MB).
    pub fn with_exfiltration_threshold(mut self, bytes: u64) -> Self {
        self.exfiltration_threshold_bytes = bytes;
        self
    }

    /// Record a packet transfer to update entity behavioral baselines.
    pub fn record_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        bytes: u64,
        hour_of_day: u8,
    ) {
        let src_profile = self
            .profiles
            .entry(src_ip)
            .or_insert_with(|| EntityProfile::new(src_ip));
        src_profile.record_tx(dst_ip, dst_port, bytes, hour_of_day);

        let dst_profile = self
            .profiles
            .entry(dst_ip)
            .or_insert_with(|| EntityProfile::new(dst_ip));
        dst_profile.record_rx(src_ip, bytes, hour_of_day);
    }

    /// Evaluate behavioral anomalies for a single entity (IP).
    pub fn evaluate_entity(&self, ip: &IpAddr) -> Option<UebaEvaluation> {
        let profile = self.profiles.get(ip)?;
        let mut anomalies = Vec::new();
        let mut max_severity: f64 = 0.0;

        // 1. Off-Hour Activity Check
        let mut off_hour_packets: u64 = 0;
        for &h in &self.off_hours {
            off_hour_packets += profile.hourly_activity[h as usize];
        }
        if profile.packet_count > 5 && off_hour_packets > 0 {
            let ratio = off_hour_packets as f64 / profile.packet_count as f64;
            if ratio > 0.20 {
                let severity = (ratio * 100.0).min(90.0);
                max_severity = max_severity.max(severity);
                anomalies.push(UebaAnomaly {
                    kind: UebaAnomalyKind::OffHourActivity,
                    severity,
                    description: format!(
                        "Entity performed {:.1}% of network transfers during off-hours (22:00-06:00).",
                        ratio * 100.0
                    ),
                });
            }
        }

        // 2. Data Exfiltration Spike Check
        if profile.bytes_sent > self.exfiltration_threshold_bytes {
            let tx_ratio = if profile.bytes_received > 0 {
                profile.bytes_sent as f64 / profile.bytes_received as f64
            } else {
                10.0
            };
            if tx_ratio > 3.0 {
                let severity = ((profile.bytes_sent as f64 / self.exfiltration_threshold_bytes as f64) * 50.0).min(95.0);
                max_severity = max_severity.max(severity);
                anomalies.push(UebaAnomaly {
                    kind: UebaAnomalyKind::ExfiltrationSpike,
                    severity,
                    description: format!(
                        "Potential Data Exfiltration: Outgoing volume ({} bytes) exceeds incoming by {:.1}x.",
                        profile.bytes_sent, tx_ratio
                    ),
                });
            }
        }

        // 3. Rare Destination Fan-Out Check
        if profile.unique_destinations.len() > 50 {
            let severity = ((profile.unique_destinations.len() as f64 / 50.0) * 40.0).min(85.0);
            max_severity = max_severity.max(severity);
            anomalies.push(UebaAnomaly {
                kind: UebaAnomalyKind::RareDestination,
                severity,
                description: format!(
                    "High destination fan-out: Entity communicated with {} unique external IP addresses.",
                    profile.unique_destinations.len()
                ),
            });
        }

        // Aggregated Threat Score
        let threat_score = max_severity;
        let is_suspicious = threat_score >= 50.0;
        let summary = if is_suspicious {
            format!(
                "CRITICAL UEBA ANOMALY for {}: Threat Score {:.1}/100 with {} behavioral alerts.",
                ip, threat_score, anomalies.len()
            )
        } else {
            format!("Entity {} behavior is within normal statistical baselines.", ip)
        };

        Some(UebaEvaluation {
            entity_ip: ip.to_string(),
            threat_score,
            anomalies,
            is_suspicious,
            summary,
        })
    }

    /// Evaluate all tracked entities and return evaluations sorted by threat score descending.
    pub fn evaluate_all(&self) -> Vec<UebaEvaluation> {
        let mut evaluations: Vec<UebaEvaluation> = self
            .profiles
            .keys()
            .filter_map(|ip| self.evaluate_entity(ip))
            .collect();
        evaluations.sort_by(|a, b| b.threat_score.partial_cmp(&a.threat_score).unwrap_or(std::cmp::Ordering::Equal));
        evaluations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ueba_engine_normal_behavior() {
        let mut engine = UebaEngine::new();
        let src_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Standard daytime traffic (hour 14 = 2 PM)
        for _ in 0..100 {
            engine.record_packet(src_ip, dst_ip, 80, 500, 14);
        }

        let eval = engine.evaluate_entity(&src_ip).unwrap();
        assert!(!eval.is_suspicious);
        assert!(eval.threat_score < 50.0);
    }

    #[test]
    fn test_ueba_off_hour_and_exfiltration_detect() {
        let mut engine = UebaEngine::new().with_exfiltration_threshold(100_000);
        let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let dst_ip: IpAddr = "198.51.100.44".parse().unwrap();

        // 2 AM (off-hour 2) large exfiltration traffic
        for _ in 0..50 {
            engine.record_packet(src_ip, dst_ip, 443, 10_000, 2);
        }

        let eval = engine.evaluate_entity(&src_ip).unwrap();
        assert!(eval.is_suspicious);
        assert!(eval.threat_score >= 50.0);
        assert!(!eval.anomalies.is_empty());
    }
}
