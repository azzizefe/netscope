// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! End-to-end pipeline throughput: how many frames per second survive the
//! lock-free ring plus the rayon dissector stage, not just `dissect()` alone.
//!
//! This is the measurement that used to be `pipeline::tests::
//! bench_pipeline_throughput`, a `#[test]` asserting `rate > 50_000.0` off a
//! single wall-clock reading. It was `#[ignore]`d because `cargo test` runs
//! tests in parallel, so the number it produced was mostly a statement about
//! how busy the machine was — and being ignored, it ran for nobody.
//!
//! Criterion is the right tool for the same question: it warms up, takes many
//! samples, reports a confidence interval, and flags outliers rather than
//! failing the build because one run landed on a busy core. `cargo bench` also
//! defaults to a release build, which the old test did not.
//!
//! Run: `cargo bench --bench pipeline_throughput`
//!
//! The correctness half — every pushed frame arriving — stayed behind as
//! `pipeline::tests::ten_thousand_frames_all_arrive`, which is deterministic
//! and no longer ignored.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use netscope_core::pipeline::{Pipeline, RawFrame};

mod common;

/// One run of the whole pipeline over `payloads`, returning what came out.
///
/// The pipeline is built and torn down inside the timed closure on purpose:
/// starting the rayon stage and joining it is part of what a capture pays, and
/// a `Pipeline` cannot be rewound for a second sample.
fn drain_pipeline(payloads: &[Vec<u8>]) -> usize {
    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = crossbeam_channel::unbounded();
    let mut pipeline = Pipeline::start(1, tx, running.clone());
    let producer = pipeline.producer();

    for (i, data) in payloads.iter().enumerate() {
        let bytes = bytes::Bytes::from(data.clone());
        let frame = RawFrame::new(i as i64, 0, data.len() as u32, bytes);
        producer.push_blocking(frame, &running);
    }
    producer.finish();
    pipeline.join();

    rx.try_iter().count()
}

fn bench_pipeline(c: &mut Criterion) {
    let payloads = common::build_mixed_packets(10_000);

    let mut g = c.benchmark_group("pipeline_throughput");
    g.throughput(Throughput::Elements(payloads.len() as u64));
    // Each sample builds and joins a pipeline over 10k frames, so the default
    // 100 samples would take minutes for a number that does not need that
    // resolution.
    g.sample_size(10);
    g.bench_function("ring_and_dissect_10k_mixed", |b| {
        b.iter(|| drain_pipeline(&payloads))
    });
    g.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
