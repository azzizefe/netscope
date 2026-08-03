// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Fuzz the packet dispatch: arbitrary bytes in, no panic out.
//!
//! `dissect()` is the single door every captured frame goes through — Ethernet,
//! then IP, then the transport, then whichever of 500-odd application dissectors
//! the port or the framing selects. It is handed bytes off the wire, so every
//! one of those layers is parsing input an attacker chooses. A panic there is
//! not a cosmetic bug: the analyser dies mid-capture, and on a live capture the
//! packets that arrive while it is down are simply gone.
//!
//! This replaces the `cargo fuzz init` template, which was still
//!
//! ```ignore
//! fuzz_target!(|data: &[u8]| {
//!     // fuzzed code goes here
//! });
//! ```
//!
//! — a target that builds, runs, reports coverage and finds nothing, for as
//! long as you care to leave it running.
//!
//! The unit suite already sweeps malformed payloads across every dispatched
//! port and the structural fall-through (`dissectors::robustness`). Those are
//! deterministic and cheap enough to run on every `cargo test`; this is the
//! other half — coverage-guided search over inputs nobody thought to write
//! down, including the link-layer and IP header fields those sweeps hold fixed.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The summary is what reaches the packet list, so touch it: a dissector
    // that formats lazily would otherwise never run the code that panics.
    let result = netscope_core::dissectors::dissect(data);
    let _ = result.summary.len();
});
