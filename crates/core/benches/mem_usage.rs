//! Memory footprint of parsed packets (ROADMAP §4.4) — not a timing
//! benchmark. A counting global allocator measures the real heap cost of
//! holding one million dissected `Packet`s, and of cloning them (which,
//! since §4.2, shares the frame bytes instead of copying them).
//!
//! Run: `cargo bench --bench mem_usage`
//! Packet count can be overridden: `MEM_PACKETS=100000 cargo bench --bench mem_usage`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::Utc;
use netscope_core::models::Packet;

mod common;

struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn fmt_bytes(b: usize) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0))
    }
}

fn dissect_to_packet(raw: &[u8]) -> Packet {
    let d = netscope_core::dissectors::dissect(raw);
    Packet {
        timestamp: Utc::now(),
        src_addr: d.src_addr,
        dst_addr: d.dst_addr,
        src_port: d.src_port,
        dst_port: d.dst_port,
        protocol: d.protocol,
        length: raw.len(),
        summary: d.summary,
        data: raw.to_vec().into(),
    }
}

fn main() {
    let n: usize = std::env::var("MEM_PACKETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    // Template frames, reused so their own cost doesn't count.
    let templates = common::build_mixed_packets(5);
    let avg_wire: usize = templates.iter().map(|t| t.len()).sum::<usize>() / templates.len();

    let before = live();
    let start = std::time::Instant::now();
    let mut store: Vec<Packet> = Vec::with_capacity(n);
    for i in 0..n {
        store.push(dissect_to_packet(&templates[i % templates.len()]));
    }
    let parse_time = start.elapsed();
    let held = live() - before;

    // Cloning shares the `Bytes` frame buffer (ROADMAP §4.2): the clone's
    // extra heap should be summaries + Vec backing, far below a deep copy.
    let before_clone = live();
    let cloned = store.clone();
    let clone_extra = live() - before_clone;

    println!("mem_usage — {n} dissected packets (avg {avg_wire} B on the wire)");
    println!(
        "  parse time        : {:.2}s ({:.0} pkt/s)",
        parse_time.as_secs_f64(),
        n as f64 / parse_time.as_secs_f64()
    );
    println!(
        "  heap held         : {} ({} per packet)",
        fmt_bytes(held),
        fmt_bytes(held / n)
    );
    println!(
        "  clone extra heap  : {} ({} per packet — Bytes are shared, not copied)",
        fmt_bytes(clone_extra),
        fmt_bytes(clone_extra / n)
    );
    println!(
        "  peak during run   : {}",
        fmt_bytes(PEAK.load(Ordering::Relaxed))
    );
    drop(cloned);
    drop(store);
}
