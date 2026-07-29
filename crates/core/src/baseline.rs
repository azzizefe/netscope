// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

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
}
