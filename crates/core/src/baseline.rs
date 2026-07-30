// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! 100% Offline Deterministic Statistical Baseline & Anomaly Engine (§6.1).
//!
//! Provides zero-token, zero-API dependency anomaly detection using:
//! - EWMA (Exponentially Weighted Moving Average)
//! - Welford's algorithm for online variance & standard deviation
//! - 168-slot (7 days x 24 hours) seasonal baseline matrix
//! - Z-score & Interquartile Range (IQR) outlier scoring
//! - Shannon entropy calculation for payload and IP/Port distributions
//! - Sliding window frequency analyzer for burst and rate anomaly detection

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::models::Packet;

/// Online running mean and variance computation using Welford's algorithm (§6.1.1).
#[derive(Debug, Clone, Default)]
pub struct WelfordTracker {
    pub count: u64,
    pub mean: f64,
    pub m2: f64,
}

impl WelfordTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn z_score(&self, x: f64) -> f64 {
        let std = self.std_dev();
        if std == 0.0 {
            0.0
        } else {
            (x - self.mean) / std
        }
    }
}

/// Exponentially Weighted Moving Average (§6.1.1).
#[derive(Debug, Clone)]
pub struct EwmaTracker {
    pub alpha: f64,
    pub current: Option<f64>,
}

impl EwmaTracker {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: alpha.clamp(0.01, 0.99),
            current: None,
        }
    }

    pub fn update(&mut self, x: f64) -> f64 {
        match self.current {
            Some(prev) => {
                let next = self.alpha * x + (1.0 - self.alpha) * prev;
                self.current = Some(next);
                next
            }
            None => {
                self.current = Some(x);
                x
            }
        }
    }

    pub fn value(&self) -> f64 {
        self.current.unwrap_or(0.0)
    }
}

/// 168-slot (7 days x 24 hours) seasonal baseline matrix (§6.1.2).
#[derive(Debug, Clone)]
pub struct SeasonalMatrix {
    /// 7 days * 24 hours = 168 slots.
    pub slots: Vec<WelfordTracker>,
}

impl Default for SeasonalMatrix {
    fn default() -> Self {
        Self::new()
    }
}

impl SeasonalMatrix {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(168);
        for _ in 0..168 {
            slots.push(WelfordTracker::new());
        }
        Self { slots }
    }

    pub fn slot_index(day_of_week: u32, hour: u32) -> usize {
        let d = (day_of_week % 7) as usize;
        let h = (hour % 24) as usize;
        d * 24 + h
    }

    pub fn record(&mut self, day_of_week: u32, hour: u32, val: f64) {
        let idx = Self::slot_index(day_of_week, hour);
        self.slots[idx].update(val);
    }

    pub fn z_score(&self, day_of_week: u32, hour: u32, val: f64) -> f64 {
        let idx = Self::slot_index(day_of_week, hour);
        self.slots[idx].z_score(val)
    }
}

/// Shannon Entropy calculator (§6.1.4).
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Shannon entropy for a list of string tokens / addresses.
pub fn calculate_distribution_entropy(tokens: &[String]) -> f64 {
    if tokens.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for t in tokens {
        *counts.entry(t.as_str()).or_default() += 1;
    }
    let total = tokens.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.values() {
        let p = c as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

/// Interquartile Range (IQR) outlier detector (§6.1.3).
pub fn is_iqr_outlier(values: &mut [f64], target: f64) -> bool {
    if values.len() < 4 {
        return false;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    let q1 = values[n / 4];
    let q3 = values[(3 * n) / 4];
    let iqr = q3 - q1;
    let lower_bound = q1 - 1.5 * iqr;
    let upper_bound = q3 + 1.5 * iqr;
    target < lower_bound || target > upper_bound
}

/// Sliding window time bucket for rate & burst tracking (§6.1.5).
#[derive(Debug, Clone)]
pub struct TimeBucket {
    pub timestamp: Instant,
    pub packets: u64,
    pub bytes: u64,
    pub conns: u64,
}

/// Sliding window frequency analyzer (§6.1.5).
#[derive(Debug, Clone)]
pub struct SlidingWindowAnalyzer {
    pub window_duration: Duration,
    pub buckets: VecDeque<TimeBucket>,
}

impl SlidingWindowAnalyzer {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_duration: Duration::from_secs(window_secs),
            buckets: VecDeque::new(),
        }
    }

    pub fn record_activity(&mut self, pkts: u64, bytes: u64, conns: u64) {
        let now = Instant::now();
        self.buckets.push_back(TimeBucket {
            timestamp: now,
            packets: pkts,
            bytes,
            conns,
        });
        self.prune(now);
    }

    pub fn prune(&mut self, now: Instant) {
        while let Some(front) = self.buckets.front() {
            if now.duration_since(front.timestamp) > self.window_duration {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.buckets.iter().map(|b| b.packets).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.buckets.iter().map(|b| b.bytes).sum()
    }

    pub fn total_conns(&self) -> u64 {
        self.buckets.iter().map(|b| b.conns).sum()
    }
}

/// Complete 100% offline, zero-token Baseline & Anomaly Engine (§6.1).
#[derive(Debug)]
pub struct BaselineEngine {
    pub pkt_rate: WelfordTracker,
    pub byte_rate: WelfordTracker,
    pub conn_rate: WelfordTracker,
    pub ewma_pkt_rate: EwmaTracker,
    pub ewma_byte_rate: EwmaTracker,
    pub seasonal: SeasonalMatrix,
    pub sliding_window: SlidingWindowAnalyzer,
    pub active_src_ips: HashSet<IpAddr>,
    pub active_dst_ips: HashSet<IpAddr>,
    pub active_dst_ports: HashSet<u16>,
}

impl Default for BaselineEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineEngine {
    pub fn new() -> Self {
        Self {
            pkt_rate: WelfordTracker::new(),
            byte_rate: WelfordTracker::new(),
            conn_rate: WelfordTracker::new(),
            ewma_pkt_rate: EwmaTracker::new(0.2),
            ewma_byte_rate: EwmaTracker::new(0.2),
            seasonal: SeasonalMatrix::new(),
            sliding_window: SlidingWindowAnalyzer::new(60),
            active_src_ips: HashSet::new(),
            active_dst_ips: HashSet::new(),
            active_dst_ports: HashSet::new(),
        }
    }

    pub fn process_packet(
        &mut self,
        packet: &Packet,
        day_of_week: u32,
        hour: u32,
    ) -> Option<String> {
        let bytes = packet.length as f64;
        self.pkt_rate.update(1.0);
        self.byte_rate.update(bytes);
        self.ewma_pkt_rate.update(1.0);
        self.ewma_byte_rate.update(bytes);
        self.seasonal.record(day_of_week, hour, bytes);
        self.sliding_window
            .record_activity(1, packet.length as u64, 1);

        if let Some(src) = packet.src_addr {
            self.active_src_ips.insert(src);
        }
        if let Some(dst) = packet.dst_addr {
            self.active_dst_ips.insert(dst);
        }
        if let Some(dpt) = packet.dst_port {
            self.active_dst_ports.insert(dpt);
        }

        // Anomaly Z-score checks
        let z_bytes = self.byte_rate.z_score(bytes);
        let z_seasonal = self.seasonal.z_score(day_of_week, hour, bytes);
        let payload_entropy = calculate_shannon_entropy(&packet.data);

        if z_bytes.abs() > 3.5 || z_seasonal.abs() > 3.5 {
            Some(format!(
                "Statistical Outlier Detected: Packet size {} bytes (Z-score: {:.2}, Seasonal Z: {:.2})",
                packet.length, z_bytes, z_seasonal
            ))
        } else if payload_entropy > 7.5 && packet.length > 256 {
            Some(format!(
                "High Entropy Payload Detected ({:.2} bits/byte) — potential encrypted C2 or exfiltration",
                payload_entropy
            ))
        } else {
            None
        }
    }
}

/// Format byte count into human readable units (e.g. 2.3 MB, 145 KB, 500 B).
pub fn format_byte_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Z-score evaluation result for a single metric.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricZScore {
    pub metric_name: String,
    pub current_value: f64,
    pub baseline_mean: f64,
    pub baseline_std: f64,
    pub z_score: f64,
    pub ratio_multiplier: f64,
}

/// Result of evaluating an event/packet against 7-day rolling sensor baselines (§1.1.4).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaselineEvaluation {
    /// Overall composite anomaly score (0.0 to 100.0)
    pub anomaly_score: f64,
    /// Individual Z-scores per metric
    pub metric_z_scores: HashMap<String, MetricZScore>,
    /// Human-readable anomaly reasons
    pub reasons: Vec<String>,
    /// Formatted human-readable explanation according to SIEM differentiation spec
    pub explanation: String,
}

/// 7-day rolling baseline data for a single host (source IP).
#[derive(Debug, Clone)]
pub struct HostBaseline {
    pub host_ip: IpAddr,
    /// Connection tracker per target IP: dst_ip -> WelfordTracker
    pub conn_counts: HashMap<IpAddr, WelfordTracker>,
    /// Observed destination IPs for this host
    pub seen_destinations: HashSet<IpAddr>,
    /// Protocol bytes: protocol_name -> (WelfordTracker for mean/std, 7d_max_bytes)
    pub protocol_bytes: HashMap<String, (WelfordTracker, u64)>,
    /// 168-slot matrix for hourly activity profile
    pub hourly_matrix: SeasonalMatrix,
}

impl HostBaseline {
    pub fn new(host_ip: IpAddr) -> Self {
        Self {
            host_ip,
            conn_counts: HashMap::new(),
            seen_destinations: HashSet::new(),
            protocol_bytes: HashMap::new(),
            hourly_matrix: SeasonalMatrix::new(),
        }
    }
}

/// 7-day rolling baseline for a specific sensor (§1.1.4).
#[derive(Debug, Clone)]
pub struct SensorBaseline {
    pub sensor_id: String,
    pub host_baselines: HashMap<IpAddr, HostBaseline>,
    pub overall_seasonal: SeasonalMatrix,
    pub pkt_rate: WelfordTracker,
    pub byte_rate: WelfordTracker,
    pub conn_rate: WelfordTracker,
}

impl SensorBaseline {
    pub fn new(sensor_id: impl Into<String>) -> Self {
        Self {
            sensor_id: sensor_id.into(),
            host_baselines: HashMap::new(),
            overall_seasonal: SeasonalMatrix::new(),
            pkt_rate: WelfordTracker::new(),
            byte_rate: WelfordTracker::new(),
            conn_rate: WelfordTracker::new(),
        }
    }

    /// Evaluates a packet against the 7-day rolling baseline for this sensor and updates baseline state.
    pub fn evaluate_and_update(
        &mut self,
        packet: &Packet,
        day_of_week: u32,
        hour: u32,
        conn_count: u64,
        dst_name: Option<&str>,
    ) -> BaselineEvaluation {
        let mut metric_z_scores = HashMap::new();
        let mut reasons = Vec::new();
        let mut max_z = 0.0f64;

        let src_ip = packet
            .src_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let dst_ip = packet
            .dst_addr
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let proto_str = packet.protocol.to_string();
        let length = packet.length as u64;

        let host_bl = self
            .host_baselines
            .entry(src_ip)
            .or_insert_with(|| HostBaseline::new(src_ip));

        // 1. Connection Frequency Anomaly (bağlantı sayısı)
        let conn_tracker = host_bl.conn_counts.entry(dst_ip).or_default();
        let conn_mean = conn_tracker.mean;
        let conn_std = conn_tracker.std_dev();
        let current_conn = conn_count.max(1) as f64;

        let conn_z = if conn_tracker.count >= 2 {
            conn_tracker.z_score(current_conn)
        } else {
            0.0
        };

        let conn_ratio = if conn_mean > 0.0 {
            current_conn / conn_mean
        } else {
            1.0
        };

        metric_z_scores.insert(
            "conn_frequency".to_string(),
            MetricZScore {
                metric_name: "conn_frequency".to_string(),
                current_value: current_conn,
                baseline_mean: conn_mean,
                baseline_std: conn_std,
                z_score: conn_z,
                ratio_multiplier: conn_ratio,
            },
        );

        if (conn_ratio >= 2.0 || conn_z > 3.0) && conn_tracker.count > 0 {
            max_z = max_z.max(conn_z.abs().max(conn_ratio));
            let dst_label = dst_name
                .map(|n| n.to_string())
                .unwrap_or_else(|| dst_ip.to_string());
            reasons.push(format!(
                "  - {}'nin {}'e bağlantı sayısı: {} (7-günlük ortalama: {:.1})\n    → Anomali skoru: +{:.0}× baseline ⚠️",
                src_ip, dst_label, current_conn as u64, conn_mean, conn_ratio
            ));
        }

        conn_tracker.update(current_conn);

        // 2. Off-Hours / Time Anomaly (zaman anomalisi)
        let slot_idx = SeasonalMatrix::slot_index(day_of_week, hour);
        let time_tracker = &host_bl.hourly_matrix.slots[slot_idx];
        let time_mean = time_tracker.mean;
        let time_std = time_tracker.std_dev();

        let time_z = if time_tracker.count >= 2 {
            time_tracker.z_score(length as f64)
        } else {
            0.0
        };

        let is_off_hours = !(6..22).contains(&hour);
        if is_off_hours && (time_tracker.count == 0 || time_mean < 50.0) {
            max_z = max_z.max(3.5);
            let hour_end = (hour + 2) % 24;
            reasons.push(format!(
                "  - {}'nin saat {:02}:00-{:02}:00 arası aktivitesi: GENELDE SIFIR\n    → Zaman anomalisi: mesai dışı ⚠️",
                src_ip, hour, hour_end
            ));
        }

        metric_z_scores.insert(
            "time_activity".to_string(),
            MetricZScore {
                metric_name: "time_activity".to_string(),
                current_value: length as f64,
                baseline_mean: time_mean,
                baseline_std: time_std,
                z_score: time_z,
                ratio_multiplier: if time_mean > 0.0 {
                    length as f64 / time_mean
                } else {
                    1.0
                },
            },
        );

        host_bl
            .hourly_matrix
            .record(day_of_week, hour, length as f64);

        // 3. New Target Anomaly (yeni hedef anomalisi)
        let is_new_target = !host_bl.seen_destinations.contains(&dst_ip);
        if is_new_target && dst_ip != IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) {
            max_z = max_z.max(3.0);
            let dst_label = dst_name
                .map(|n| n.to_string())
                .unwrap_or_else(|| dst_ip.to_string());
            reasons.push(format!(
                "  - {}'nin {}'e erişimi: İLK KEZ (daha önce hiç olmamış)\n    → Yeni hedef anomalisi ⚠️",
                src_ip, dst_label
            ));
            host_bl.seen_destinations.insert(dst_ip);
        }

        // 4. Data Volume Anomaly (veri hacmi anomalisi)
        let (proto_tracker, max_bytes_7d) = host_bl
            .protocol_bytes
            .entry(proto_str.clone())
            .or_insert_with(|| (WelfordTracker::new(), 0));

        let current_bytes = length;
        let prev_max = *max_bytes_7d;

        if prev_max > 0 && current_bytes > prev_max {
            let volume_ratio = current_bytes as f64 / prev_max as f64;
            if volume_ratio >= 2.0 {
                max_z = max_z.max(volume_ratio * 2.0);
                reasons.push(format!(
                    "  - {} veri transferi: {} (bu host için 7-gün max: {})\n    → Veri hacmi anomalisi: +{:.0}× baseline ❌",
                    proto_str,
                    format_byte_size(current_bytes),
                    format_byte_size(prev_max),
                    volume_ratio
                ));
            }
        }

        let vol_z = if proto_tracker.count >= 2 {
            proto_tracker.z_score(current_bytes as f64)
        } else {
            0.0
        };

        metric_z_scores.insert(
            "data_volume".to_string(),
            MetricZScore {
                metric_name: "data_volume".to_string(),
                current_value: current_bytes as f64,
                baseline_mean: proto_tracker.mean,
                baseline_std: proto_tracker.std_dev(),
                z_score: vol_z,
                ratio_multiplier: if prev_max > 0 {
                    current_bytes as f64 / prev_max as f64
                } else {
                    1.0
                },
            },
        );

        proto_tracker.update(current_bytes as f64);
        if current_bytes > *max_bytes_7d {
            *max_bytes_7d = current_bytes;
        }

        // Overall Anomaly Score calculation
        let calculated_anomaly_score = if reasons.is_empty() {
            0.0
        } else {
            (max_z * 15.0 + reasons.len() as f64 * 10.0).clamp(10.0, 100.0)
        };

        let explanation = if reasons.is_empty() {
            "Bu event için normalden sapma tespit edilmedi.".to_string()
        } else {
            format!(
                "Bu event'in normalden sapma derecesi:\n{}",
                reasons.join("\n")
            )
        };

        BaselineEvaluation {
            anomaly_score: calculated_anomaly_score,
            metric_z_scores,
            reasons,
            explanation,
        }
    }
}

/// Global Sensor Baseline Manager.
#[derive(Debug, Default, Clone)]
pub struct SensorBaselineManager {
    pub sensors: HashMap<String, SensorBaseline>,
}

impl SensorBaselineManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create_sensor(&mut self, sensor_id: &str) -> &mut SensorBaseline {
        self.sensors
            .entry(sensor_id.to_string())
            .or_insert_with(|| SensorBaseline::new(sensor_id))
    }

    pub fn evaluate_packet(
        &mut self,
        sensor_id: &str,
        packet: &Packet,
        day_of_week: u32,
        hour: u32,
        conn_count: u64,
        dst_name: Option<&str>,
    ) -> BaselineEvaluation {
        let sensor = self.get_or_create_sensor(sensor_id);
        sensor.evaluate_and_update(packet, day_of_week, hour, conn_count, dst_name)
    }
}

pub fn global_baseline_manager() -> &'static std::sync::Mutex<SensorBaselineManager> {
    static MGR: std::sync::OnceLock<std::sync::Mutex<SensorBaselineManager>> =
        std::sync::OnceLock::new();
    MGR.get_or_init(|| std::sync::Mutex::new(SensorBaselineManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_welford_variance_and_zscore() {
        let mut tracker = WelfordTracker::new();
        let samples = vec![10.0, 12.0, 10.0, 11.0, 9.0, 10.0];
        for s in samples {
            tracker.update(s);
        }
        assert!(tracker.mean > 9.5 && tracker.mean < 11.0);
        assert!(tracker.std_dev() > 0.5);

        let z_normal = tracker.z_score(10.5);
        assert!(z_normal.abs() < 1.0);

        let z_outlier = tracker.z_score(100.0);
        assert!(z_outlier > 5.0);
    }

    #[test]
    fn test_ewma_tracker() {
        let mut ewma = EwmaTracker::new(0.5);
        assert_eq!(ewma.update(10.0), 10.0);
        assert_eq!(ewma.update(20.0), 15.0);
    }

    #[test]
    fn test_seasonal_matrix() {
        let mut matrix = SeasonalMatrix::new();
        // Monday 09:00 = day 0, hour 9
        matrix.record(0, 9, 500.0);
        matrix.record(0, 9, 520.0);
        let z = matrix.z_score(0, 9, 510.0);
        assert!(z.abs() < 2.0);
    }

    #[test]
    fn test_shannon_entropy() {
        // Uniform bytes (low entropy)
        let zeros = vec![0u8; 100];
        assert_eq!(calculate_shannon_entropy(&zeros), 0.0);

        // All 256 byte values equally distributed (max entropy 8.0)
        let mut all_bytes = Vec::new();
        for b in 0..=255 {
            all_bytes.push(b);
        }
        let e = calculate_shannon_entropy(&all_bytes);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_sliding_window_analyzer() {
        let mut window = SlidingWindowAnalyzer::new(10);
        window.record_activity(5, 500, 1);
        assert_eq!(window.total_packets(), 5);
        assert_eq!(window.total_bytes(), 500);
    }

    #[test]
    fn test_katman_4_behavioral_baseline_and_zscore() {
        use crate::models::Protocol;
        use bytes::Bytes;
        use chrono::Utc;

        let mut mgr = SensorBaselineManager::new();
        let sensor_id = "sensor_istanbul_01";

        let pkt1 = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.1.47".parse().unwrap()),
            dst_addr: Some("10.0.5.18".parse().unwrap()),
            src_port: Some(49152),
            dst_port: Some(445),
            protocol: Protocol::Smb,
            length: 145 * 1024, // 145 KB
            summary: "SMB Read Request".to_string(),
            data: Bytes::from(vec![0u8; 100]),
            llm: None,
        };

        // Initialize baseline with historical packets
        let eval1 = mgr.evaluate_packet(sensor_id, &pkt1, 0, 14, 1, Some("FIN-DB-01"));
        assert!(eval1.reasons.iter().any(|r| r.contains("İLK KEZ")));

        // Second packet with high volume & off-hours
        let pkt_anomaly = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.1.47".parse().unwrap()),
            dst_addr: Some("10.0.5.18".parse().unwrap()),
            src_port: Some(49152),
            dst_port: Some(445),
            protocol: Protocol::Smb,
            length: 2300 * 1024, // 2.3 MB
            summary: "SMB Large Data Transfer".to_string(),
            data: Bytes::from(vec![0u8; 100]),
            llm: None,
        };

        let eval2 = mgr.evaluate_packet(sensor_id, &pkt_anomaly, 0, 3, 47, Some("FIN-DB-01"));
        assert!(eval2.anomaly_score >= 10.0);
        assert!(!eval2.metric_z_scores.is_empty());
        assert!(eval2.explanation.contains("normalden sapma derecesi"));
        assert!(
            eval2.explanation.contains("Zaman anomalisi: mesai dışı")
                || eval2.explanation.contains("Veri hacmi anomalisi")
        );
    }

    #[test]
    fn test_format_byte_size() {
        assert_eq!(format_byte_size(500), "500 B");
        assert_eq!(format_byte_size(145 * 1024), "145.0 KB");
        assert_eq!(format_byte_size(2300 * 1024), "2.2 MB");
    }
}
