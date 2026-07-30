// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
//! Parallel capture pipeline — the architecture from ROADMAP §2.1:
//!
//! ```text
//! ┌─────────────┐    ┌──────────────┐    ┌────────────────┐
//! │ Capture     │───▶│ Ring Buffer  │───▶│ Dissector Pool │───▶ Sender<Packet>
//! │ (OS thread) │    │ (lock-free)  │    │ (rayon)        │
//! └─────────────┘    └──────────────┘    └────────────────┘
//! ```
//!
//! The capture thread's only jobs are pulling frames off the wire and pushing
//! them into a lock-free ring ([`crossbeam_queue::ArrayQueue`]) — it never
//! parses, so it keeps up with bursts that used to stall the old
//! capture-and-dissect-in-one-thread loop. A dissector stage drains the ring
//! in batches and parses them across all cores with rayon, preserving arrival
//! order, then forwards finished [`Packet`]s downstream.
//!
//! Backpressure policy mirrors what kernels do:
//! * **live capture** never blocks the wire loop — when the ring is full the
//!   frame is counted in [`StatsSnapshot::dropped`] and discarded;
//! * **offline reads** block until space frees up, because dropping packets
//!   from a file would silently corrupt analysis.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;

use crate::dissectors;
use crate::llm_analytics;
use crate::models::Packet;

/// Default ring size. 64k frames ≈ a full second of 10GbE minimum-size burst
/// headroom, at ~48 bytes of queue overhead per slot.
pub const DEFAULT_RING_CAPACITY: usize = 65_536;

/// Frames drained per dissector pass.
const BATCH: usize = 512;

/// Below this many frames a batch is parsed inline — rayon's fork/join
/// overhead only pays off once there is real work to split.
const PARALLEL_THRESHOLD: usize = 32;

use bytes::Bytes;

/// A captured-but-not-yet-dissected frame, as cheap as the capture thread can
/// make it: timestamp fields plus the raw bytes (§5.2.3 zero-copy pipeline).
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// Seconds since the Unix epoch.
    pub ts_sec: i64,
    /// Nanosecond part of the timestamp.
    pub ts_nanos: u32,
    /// Original on-wire length (may exceed `data.len()` under snaplen).
    pub orig_len: u32,
    /// Captured bytes using zero-copy ref-counted `Bytes` buffer (§5.2.3).
    pub data: Bytes,
    /// Whether timestamp originated from NIC hardware clock (§5.2.4).
    pub hw_timestamp: bool,
    /// Sampling ratio applied to this frame (1 for full capture, N for 1:N sampling) (§5.2.6).
    pub sampling_ratio: u32,
}

impl RawFrame {
    pub fn new(ts_sec: i64, ts_nanos: u32, orig_len: u32, data: impl Into<Bytes>) -> Self {
        Self {
            ts_sec,
            ts_nanos,
            orig_len,
            data: data.into(),
            hw_timestamp: false,
            sampling_ratio: 1,
        }
    }

    pub fn with_hw_timestamp(mut self, hw_ts: bool) -> Self {
        self.hw_timestamp = hw_ts;
        self
    }

    pub fn with_sampling_ratio(mut self, ratio: u32) -> Self {
        self.sampling_ratio = ratio;
        self
    }
}

/// Dynamic adaptive packet sampling engine (§5.2.6).
/// Scales sampling ratio (1:1 -> 1:N -> 1:1) dynamically based on CPU load and queue capacity.
#[derive(Debug)]
pub struct AdaptiveSampler {
    pub cpu_threshold_percent: u32,
    pub queue_threshold_percent: u32,
    current_ratio: AtomicU64,
    sampled_out_count: AtomicU64,
}

impl Default for AdaptiveSampler {
    fn default() -> Self {
        Self::new(90, 85)
    }
}

impl AdaptiveSampler {
    pub fn new(cpu_threshold_percent: u32, queue_threshold_percent: u32) -> Self {
        Self {
            cpu_threshold_percent,
            queue_threshold_percent,
            current_ratio: AtomicU64::new(1),
            sampled_out_count: AtomicU64::new(0),
        }
    }

    /// Evaluates whether an incoming packet should be kept or sampled out.
    /// Returns `(should_keep, applied_sampling_ratio)`.
    pub fn should_sample(
        &self,
        packet_idx: u64,
        ring_fill_pct: u32,
        cpu_fill_pct: u32,
    ) -> (bool, u32) {
        let current = self.current_ratio.load(Ordering::Relaxed);
        let mut target = current;

        if cpu_fill_pct >= self.cpu_threshold_percent
            || ring_fill_pct >= self.queue_threshold_percent
        {
            if target < 16 {
                target = (target * 2).min(16);
                self.current_ratio.store(target, Ordering::Relaxed);
            }
        } else if cpu_fill_pct < self.cpu_threshold_percent.saturating_sub(15)
            && ring_fill_pct < self.queue_threshold_percent.saturating_sub(20)
            && target > 1
        {
            target = (target / 2).max(1);
            self.current_ratio.store(target, Ordering::Relaxed);
        }

        let ratio = target as u32;
        if ratio <= 1 {
            (true, 1)
        } else {
            let keep = packet_idx.is_multiple_of(ratio as u64);
            if !keep {
                self.sampled_out_count.fetch_add(1, Ordering::Relaxed);
            }
            (keep, ratio)
        }
    }

    pub fn current_ratio(&self) -> u32 {
        self.current_ratio.load(Ordering::Relaxed) as u32
    }

    pub fn sampled_out_count(&self) -> u64 {
        self.sampled_out_count.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Counters {
    received: AtomicU64,
    dropped: AtomicU64,
    dissected: AtomicU64,
    sampled_out: AtomicU64,
    hw_timestamped: AtomicU64,
}

/// Point-in-time pipeline counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Frames handed to the pipeline by the capture side.
    pub received: u64,
    /// Frames discarded because the ring was full (live capture only).
    pub dropped: u64,
    /// Frames dissected and forwarded downstream.
    pub dissected: u64,
    /// Frames dropped by adaptive sampling (§5.2.6).
    pub sampled_out: u64,
    /// Frames tagged with NIC hardware timestamp (§5.2.4).
    pub hw_timestamped: u64,
}

/// The capture side's handle: push frames, then declare the stream finished.
/// Cheap to clone; all clones feed the same ring.
#[derive(Clone)]
pub struct Producer {
    ring: Arc<ArrayQueue<RawFrame>>,
    counters: Arc<Counters>,
    done: Arc<AtomicBool>,
}

impl Producer {
    /// Push without ever blocking — full ring means the frame is dropped and
    /// counted, exactly like a kernel buffer overflow. For live capture.
    pub fn push_live(&self, frame: RawFrame) {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        if frame.hw_timestamp {
            self.counters.hw_timestamped.fetch_add(1, Ordering::Relaxed);
        }
        if self.ring.push(frame).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a frame dropped by adaptive sampling (§5.2.6).
    pub fn push_sampled_out(&self) {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        self.counters.sampled_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Push with backpressure — waits for ring space so nothing is lost. For
    /// offline file reads. Returns `false` (frame not queued) once
    /// `keep_running` goes false, so a cancelled load exits promptly.
    pub fn push_blocking(&self, frame: RawFrame, keep_running: &AtomicBool) -> bool {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        let mut frame = frame;
        loop {
            match self.ring.push(frame) {
                Ok(()) => return true,
                Err(back) => {
                    if !keep_running.load(Ordering::SeqCst) {
                        self.counters.received.fetch_sub(1, Ordering::Relaxed);
                        return false;
                    }
                    frame = back;
                    thread::sleep(Duration::from_micros(200));
                }
            }
        }
    }

    /// Declare that no more frames will arrive. The dissector stage drains
    /// what is queued and then exits.
    pub fn finish(&self) {
        self.done.store(true, Ordering::Release);
    }
}

/// The running pipeline: owns the dissector stage. Get a [`Producer`] with
/// [`Pipeline::producer`], feed it, call `finish()`, then [`Pipeline::join`].
pub struct Pipeline {
    producer: Producer,
    handle: Option<JoinHandle<()>>,
}

impl Pipeline {
    /// Start a pipeline with the default ring capacity. `linktype` is the
    /// capture's DLT (decides Ethernet vs. 802.11 dissection); finished
    /// packets go out through `tx`. If the receiving side of `tx` disappears,
    /// the pipeline stores `false` into `running` so the capture loop watching
    /// that flag also winds down.
    pub fn start(linktype: i32, tx: Sender<Packet>, running: Arc<AtomicBool>) -> Self {
        Self::with_capacity(DEFAULT_RING_CAPACITY, linktype, tx, running)
    }

    /// [`Pipeline::start`] with an explicit ring capacity (tests, tuning).
    pub fn with_capacity(
        capacity: usize,
        linktype: i32,
        tx: Sender<Packet>,
        running: Arc<AtomicBool>,
    ) -> Self {
        let producer = Producer {
            ring: Arc::new(ArrayQueue::new(capacity.max(2))),
            counters: Arc::new(Counters::default()),
            done: Arc::new(AtomicBool::new(false)),
        };
        let ring = producer.ring.clone();
        let counters = producer.counters.clone();
        let done = producer.done.clone();

        let handle = thread::Builder::new()
            .name("dissect".into())
            .spawn(move || {
                let mut batch: Vec<RawFrame> = Vec::with_capacity(BATCH);
                loop {
                    batch.clear();
                    while batch.len() < BATCH {
                        match ring.pop() {
                            Some(f) => batch.push(f),
                            None => break,
                        }
                    }
                    if batch.is_empty() {
                        if done.load(Ordering::Acquire) && ring.is_empty() {
                            break;
                        }
                        thread::sleep(Duration::from_micros(500));
                        continue;
                    }

                    let packets = dissect_batch(std::mem::take(&mut batch), linktype);
                    counters
                        .dissected
                        .fetch_add(packets.len() as u64, Ordering::Relaxed);
                    for pkt in packets {
                        if tx.send(pkt).is_err() {
                            // Consumer hung up — tell the capture loop, too.
                            running.store(false, Ordering::SeqCst);
                            return;
                        }
                    }
                }
            })
            .expect("failed to spawn dissector thread");

        Self {
            producer,
            handle: Some(handle),
        }
    }

    /// Handle for the capture side.
    pub fn producer(&self) -> Producer {
        self.producer.clone()
    }

    /// Current counters.
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            received: self.producer.counters.received.load(Ordering::Relaxed),
            dropped: self.producer.counters.dropped.load(Ordering::Relaxed),
            dissected: self.producer.counters.dissected.load(Ordering::Relaxed),
            sampled_out: self.producer.counters.sampled_out.load(Ordering::Relaxed),
            hw_timestamped: self
                .producer
                .counters
                .hw_timestamped
                .load(Ordering::Relaxed),
        }
    }

    /// Wait for the dissector stage to drain and exit. Call after the
    /// producer has called [`Producer::finish`] (joining earlier would wait
    /// forever on a live stream).
    pub fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        // Make an un-joined drop terminate rather than leak a spinning thread.
        self.producer.finish();
        self.join();
    }
}

/// Dissect a batch, in parallel when it's big enough to be worth it. Order is
/// preserved either way — `collect` on an indexed parallel iterator keeps
/// positions — so downstream consumers still see arrival order.
fn dissect_batch(batch: Vec<RawFrame>, linktype: i32) -> Vec<Packet> {
    use rayon::prelude::*;
    if batch.len() >= PARALLEL_THRESHOLD {
        batch
            .into_par_iter()
            .map(|f| dissect_frame(f, linktype))
            .collect()
    } else {
        batch
            .into_iter()
            .map(|f| dissect_frame(f, linktype))
            .collect()
    }
}

/// One frame → one dissected [`Packet`].
pub(crate) fn dissect_frame(frame: RawFrame, linktype: i32) -> Packet {
    let timestamp =
        chrono::DateTime::from_timestamp(frame.ts_sec, frame.ts_nanos).unwrap_or_default();
    let d = dissectors::dissect_linktype(&frame.data, linktype);
    let llm = llm_analytics::extract_llm_metadata(&frame.data, &d.protocol);
    Packet {
        timestamp,
        src_addr: d.src_addr,
        dst_addr: d.dst_addr,
        src_port: d.src_port,
        dst_port: d.dst_port,
        protocol: d.protocol,
        length: frame.orig_len as usize,
        summary: d.summary,
        data: frame.data,
        llm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{
        build_dns_query, build_tcp_packet, build_udp_packet, TcpFlags,
    };
    use crate::models::Protocol;

    fn frame(i: usize, data: Vec<u8>) -> RawFrame {
        RawFrame::new(
            1_700_000_000 + i as i64,
            0,
            data.len() as u32,
            Bytes::from(data),
        )
    }

    #[test]
    fn test_adaptive_sampler_dynamics() {
        let sampler = AdaptiveSampler::new(90, 85);
        assert_eq!(sampler.current_ratio(), 1);

        // Low pressure -> 1:1 sampling
        let (keep, ratio) = sampler.should_sample(0, 10, 20);
        assert!(keep);
        assert_eq!(ratio, 1);

        // High CPU pressure (>90%) -> scale up sampling ratio to 1:2
        let (_, ratio) = sampler.should_sample(1, 10, 95);
        assert_eq!(ratio, 2);

        // High queue pressure (>85%) -> scale up sampling ratio to 1:4
        let (_, ratio) = sampler.should_sample(2, 90, 20);
        assert_eq!(ratio, 4);

        // Normal pressure drops -> scale back down towards 1:1
        let _ = sampler.should_sample(3, 10, 10);
        assert!(sampler.current_ratio() <= 2);
    }

    #[test]
    fn dissects_in_order_across_batches() {
        const COUNT: usize = 2_000;
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut pipeline = Pipeline::with_capacity(256, 1, tx, running.clone());
        let producer = pipeline.producer();

        for i in 0..COUNT {
            let data = if i % 2 == 0 {
                build_tcp_packet(
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    12345,
                    80,
                    TcpFlags {
                        ack: true,
                        ..Default::default()
                    },
                    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
            } else {
                let dns = build_dns_query("example.com", i as u16);
                build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns)
            };
            assert!(producer.push_blocking(frame(i, data), &running));
        }
        producer.finish();
        pipeline.join();

        let packets: Vec<Packet> = rx.try_iter().collect();
        assert_eq!(packets.len(), COUNT);
        for (i, pkt) in packets.iter().enumerate() {
            // Arrival order must survive the parallel stage:
            assert_eq!(pkt.timestamp.timestamp(), 1_700_000_000 + i as i64);
            let expect = if i % 2 == 0 {
                Protocol::Http
            } else {
                Protocol::Dns
            };
            assert_eq!(pkt.protocol, expect, "packet {i}");
        }

        let stats = pipeline.stats();
        assert_eq!(stats.received, COUNT as u64);
        assert_eq!(stats.dissected, COUNT as u64);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn live_push_drops_when_ring_is_full() {
        // A producer with no dissector attached: the ring can only fill up.
        let producer = Producer {
            ring: Arc::new(ArrayQueue::new(2)),
            counters: Arc::new(Counters::default()),
            done: Arc::new(AtomicBool::new(false)),
        };
        for i in 0..5 {
            producer.push_live(frame(i, vec![0u8; 10]));
        }
        assert_eq!(producer.counters.received.load(Ordering::Relaxed), 5);
        assert_eq!(producer.counters.dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn blocking_push_aborts_when_stopped() {
        let producer = Producer {
            ring: Arc::new(ArrayQueue::new(1)),
            counters: Arc::new(Counters::default()),
            done: Arc::new(AtomicBool::new(false)),
        };
        let running = AtomicBool::new(true);
        assert!(producer.push_blocking(frame(0, vec![1]), &running));
        // Ring is now full and nothing drains it; a stopped flag must bail out.
        running.store(false, Ordering::SeqCst);
        assert!(!producer.push_blocking(frame(1, vec![2]), &running));
    }

    #[test]
    fn consumer_disconnect_clears_running_flag() {
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut pipeline = Pipeline::with_capacity(64, 1, tx, running.clone());
        let producer = pipeline.producer();
        drop(rx); // consumer goes away

        producer.push_live(frame(
            0,
            build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1,
                2,
                TcpFlags {
                    syn: true,
                    ..Default::default()
                },
                &[],
            ),
        ));
        // The dissector notices the dead channel on its next send and stops
        // the shared running flag.
        for _ in 0..200 {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!running.load(Ordering::SeqCst));
        producer.finish();
        pipeline.join();
    }

    /// Throughput measurement mirroring `bench_dissect_throughput`, but
    /// through the whole ring + rayon pipeline — and ignored by default for the
    /// same reason: it asserts on wall-clock rate, so under `cargo test`'s
    /// parallel load it measures how busy the machine is rather than what the
    /// pipeline costs. Left un-ignored it fails on loaded machines and slow CI
    /// runners for reasons that have nothing to do with the code, which is a
    /// bad first impression for anyone who just cloned the repo.
    ///
    /// Nothing functional is lost: `dissects_in_order_across_batches` already
    /// asserts every pushed frame comes out, in order, without timing anything.
    ///
    /// Run it on its own:
    ///   cargo test --release bench_pipeline_throughput -- --ignored --nocapture
    #[test]
    #[ignore = "timing-sensitive: measures machine load when run in parallel"]
    fn bench_pipeline_throughput() {
        const COUNT: usize = 10_000;
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut pipeline = Pipeline::start(1, tx, running.clone());
        let producer = pipeline.producer();

        let payloads: Vec<Vec<u8>> = (0..COUNT)
            .map(|i| {
                build_tcp_packet(
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    12345,
                    80,
                    TcpFlags {
                        ack: true,
                        ..Default::default()
                    },
                    if i % 2 == 0 {
                        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice()
                    },
                )
            })
            .collect();

        let start = std::time::Instant::now();
        for (i, data) in payloads.into_iter().enumerate() {
            assert!(producer.push_blocking(frame(i, data), &running));
        }
        producer.finish();
        pipeline.join();
        let elapsed = start.elapsed();

        let n = rx.try_iter().count();
        assert_eq!(n, COUNT);
        let rate = COUNT as f64 / elapsed.as_secs_f64();
        println!("Pipeline: {COUNT} packets in {elapsed:?} → {rate:.0} pkt/s");
        // Keep a conservative floor so CI boxes don't flake.
        assert!(rate > 50_000.0, "pipeline too slow: {rate:.0} pkt/s");
    }
}
