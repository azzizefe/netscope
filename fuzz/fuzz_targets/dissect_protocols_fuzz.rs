// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Protocol Dissector Fuzz Target: validate payload dissection robustness.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Direct packet dissection
    let result = netscope_core::dissectors::dissect(data);
    let _ = result.summary.len();

    // 2. Heuristic signature validation fuzzing
    let _ = netscope_core::dissectors::heuristics::matches_magic(data, b"PQC\x01");
    let _ = netscope_core::dissectors::heuristics::inspect_pqc_frame(data);
    let _ = netscope_core::dissectors::heuristics::inspect_canopen_frame(data);
});
