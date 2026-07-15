// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Dissection throughput (ROADMAP §4.4): how many packets per second the
//! full `dissect()` chain (Ethernet → IP → TCP/UDP → app layer) handles.
//!
//! Run: `cargo bench --bench parse_throughput`

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

mod common;

fn bench_mixed(c: &mut Criterion) {
    let packets = common::build_mixed_packets(10_000);
    let mut g = c.benchmark_group("parse_throughput");
    g.throughput(Throughput::Elements(packets.len() as u64));
    g.bench_function("dissect_10k_mixed", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for p in &packets {
                total += netscope_core::dissectors::dissect(black_box(p))
                    .summary
                    .len();
            }
            total
        })
    });
    g.finish();
}

fn bench_per_protocol(c: &mut Criterion) {
    let http = common::build_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        false,
        true,
        b"GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n",
    );
    let dns_payload = common::build_dns_query("subdomain.example.com", 7);
    let dns = common::build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns_payload);
    // Payload on an unclaimed port exercises the worst case: every
    // any-port heuristic (WebSocket, HTTP/2, plugins) runs and misses.
    let unknown = common::build_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        50000,
        8080,
        false,
        true,
        b"neither http nor websocket, just application bytes rolling by....",
    );

    let mut g = c.benchmark_group("parse_single");
    for (name, pkt) in [("http", &http), ("dns", &dns), ("unknown_port", &unknown)] {
        g.throughput(Throughput::Elements(1));
        g.bench_function(name, |b| {
            b.iter(|| netscope_core::dissectors::dissect(black_box(pkt)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench_mixed, bench_per_protocol);
criterion_main!(benches);
