// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PIM message (IP protocol 103) — Protocol Independent Multicast
/// routing. The high nibble of byte 0 is the version, the low nibble the
/// message type (RFC 7761).
pub fn dissect_pim(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&b) => {
            let version = b >> 4;
            let name = match b & 0x0F {
                0 => "Hello",
                1 => "Register",
                2 => "Register-Stop",
                3 => "Join/Prune",
                4 => "Bootstrap",
                5 => "Assert",
                6 => "Graft",
                7 => "Graft-Ack",
                8 => "Candidate-RP-Advertisement",
                _ => "message",
            };
            format!("PIMv{version} {name}")
        }
        None => "PIM (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Pim,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello() {
        let r = dissect_pim(None, None, &[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Pim);
        assert_eq!(r.summary, "PIMv2 Hello");
    }

    #[test]
    fn join_prune() {
        let r = dissect_pim(None, None, &[0x23]);
        assert_eq!(r.summary, "PIMv2 Join/Prune");
    }
}
