// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
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
use crate::models::Packet;

/// Default ring size. 64k frames ≈ a full second of 10GbE minimum-size burst
/// headroom, at ~48 bytes of queue overhead per slot.
pub const DEFAULT_RING_CAPACITY: usize = 65_536;

/// Frames drained per dissector pass.
const BATCH: usize = 512;

/// Below this many frames a batch is parsed inline — rayon's fork/join
/// overhead only pays off once there is real work to split.
const PARALLEL_THRESHOLD: usize = 32;

/// A captured-but-not-yet-dissected frame, as cheap as the capture thread can
/// make it: timestamp fields plus the raw bytes.
#[derive(Debug)]
pub struct RawFrame {
    /// Seconds since the Unix epoch.
    pub ts_sec: i64,
    /// Nanosecond part of the timestamp.
    pub ts_nanos: u32,
    /// Original on-wire length (may exceed `data.len()` under snaplen).
    pub orig_len: u32,
    /// Captured bytes.
    pub data: Vec<u8>,
}

#[derive(Default)]
struct Counters {
    received: AtomicU64,
    dropped: AtomicU64,
    dissected: AtomicU64,
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
        if self.ring.push(frame).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
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
    Packet {
        timestamp,
        src_addr: d.src_addr,
        dst_addr: d.dst_addr,
        src_port: d.src_port,
        dst_port: d.dst_port,
        protocol: d.protocol,
        length: frame.orig_len as usize,
        summary: d.summary,
        data: frame.data.into(),
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
        RawFrame {
            ts_sec: 1_700_000_000 + i as i64,
            ts_nanos: 0,
            orig_len: data.len() as u32,
            data,
        }
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

    /// Throughput sanity check mirroring `bench_dissect_throughput`, but
    /// through the whole ring + rayon pipeline.
    #[test]
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
