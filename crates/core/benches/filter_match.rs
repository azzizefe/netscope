// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Display-filter evaluation speed (ROADMAP §4.4): 100k match calls across a
//! representative set of filter expressions, from a bare protocol word to
//! frame-parsing fields like `http.request.method`.
//!
//! Run: `cargo bench --bench filter_match`

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use netscope_core::filter::Filter;
use netscope_core::models::Packet;
use std::hint::black_box;

mod common;

/// Dissect raw frames into `Packet`s the way the pipeline does.
fn packets(count: usize) -> Vec<Packet> {
    common::build_mixed_packets(count)
        .into_iter()
        .map(|raw| {
            let d = netscope_core::dissectors::dissect(&raw);
            Packet {
                timestamp: Utc::now(),
                src_addr: d.src_addr,
                dst_addr: d.dst_addr,
                src_port: d.src_port,
                dst_port: d.dst_port,
                protocol: d.protocol,
                length: raw.len(),
                summary: d.summary,
                data: raw.into(),
            }
        })
        .collect()
}

fn bench_filters(c: &mut Criterion) {
    let pkts = packets(10_000);
    let filters: Vec<(&str, Filter)> = [
        "tcp",
        "ip.addr == 10.0.0.1 && tcp.port == 443",
        "http.request.method == GET",
        "dns.qry.name contains example",
        "info contains \"HTTP\"",
        "tcp.flags.syn == 1 && !dns",
        "(tls || http) && frame.len > 60",
        "udp.port == 53 || tcp.port == 80",
        "ip.src == 10.0.0.1",
        "frame.len > 100",
    ]
    .into_iter()
    .map(|s| (s, Filter::parse(s).expect(s)))
    .collect();

    // 10 filters × 10k packets = the roadmap's 100k evaluations per iteration.
    let mut g = c.benchmark_group("filter_match");
    g.throughput(Throughput::Elements((filters.len() * pkts.len()) as u64));
    g.bench_function("100k_evals_mixed", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for (_, f) in &filters {
                for p in &pkts {
                    if f.matches(black_box(p)) {
                        hits += 1;
                    }
                }
            }
            hits
        })
    });
    g.finish();

    // Per-filter cost, one packet — spotlights the expensive field types.
    let mut g = c.benchmark_group("filter_single");
    let p = &pkts[0]; // the HTTP GET packet
    for (name, f) in &filters {
        g.throughput(Throughput::Elements(1));
        g.bench_function(*name, |b| b.iter(|| f.matches(black_box(p))));
    }
    g.finish();
}

criterion_group!(benches, bench_filters);
criterion_main!(benches);
