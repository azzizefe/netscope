// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a VTP frame (LLC/SNAP, Cisco OUI, PID 0x2003) — VLAN Trunking
/// Protocol, which propagates the VLAN database between Cisco switches. Byte 1
/// is the message code.
pub fn dissect_vtp(body: &[u8]) -> DissectedResult {
    let summary = match body.get(1) {
        Some(&code) => {
            let name = match code {
                1 => "Summary Advertisement",
                2 => "Subset Advertisement",
                3 => "Advertisement Request",
                4 => "Join",
                _ => "message",
            };
            format!("VTP {name}")
        }
        None => "VTP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Vtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_advertisement() {
        let r = dissect_vtp(&[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Vtp);
        assert_eq!(r.summary, "VTP Summary Advertisement");
    }
}
