// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an L2TP message (UDP 1701) — a tunnelling protocol often paired
/// with IPsec for VPNs. The first 16 bits are flags; the top bit (T) marks a
/// control message, the low nibble is the version (RFC 2661).
pub fn dissect_l2tp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let version = flags & 0x000F;
        let kind = if flags & 0x8000 != 0 {
            "control message"
        } else {
            "data message"
        };
        format!("L2TPv{version} {kind}")
    } else {
        "L2TP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::L2tp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_message() {
        // T + L + S bits set, version 2 = 0xC802.
        let r = dissect_l2tp(None, None, 1701, 1701, &[0xC8, 0x02, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::L2tp);
        assert_eq!(r.summary, "L2TPv2 control message");
    }
}
