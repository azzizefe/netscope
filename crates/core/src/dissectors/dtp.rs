// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DTP frame (LLC/SNAP, Cisco OUI, PID 0x2004) — Dynamic Trunking
/// Protocol, which negotiates whether a switch port becomes a trunk. Leaving it
/// enabled on access ports is what makes VLAN-hopping attacks possible, so its
/// presence is worth noticing.
pub fn dissect_dtp(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(&version) => format!("DTP v{version} — trunk negotiation"),
        None => "DTP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Dtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        let r = dissect_dtp(&[0x01, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Dtp);
        assert_eq!(r.summary, "DTP v1 — trunk negotiation");
    }
}
