// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PAgP frame (LLC/SNAP, Cisco OUI, PID 0x0104) — Port Aggregation
/// Protocol, Cisco's proprietary way of bundling links into an EtherChannel
/// (the counterpart to standard LACP).
pub fn dissect_pagp(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(&version) => format!("PAgP v{version} — EtherChannel negotiation"),
        None => "PAgP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Pagp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        let r = dissect_pagp(&[0x01, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Pagp);
        assert!(r.summary.contains("EtherChannel"), "{}", r.summary);
    }
}
