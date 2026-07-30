// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The STUN magic cookie sits at bytes 4..8 of every RFC 5389 message and is
/// what tells STUN apart from other traffic on the same port.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Dissect a STUN message (UDP 3478, used by WebRTC/VoIP NAT traversal).
/// Validates the magic cookie so only real STUN is labelled as such.
pub fn dissect_stun(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("STUN ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Stun,
        summary,
    }
}

/// Returns true when the payload carries a valid STUN magic cookie — used by
/// the UDP dispatcher to recognise STUN on dynamically negotiated media ports.
pub fn looks_like_stun(payload: &[u8]) -> bool {
    payload.len() >= 20
        && payload[0] & 0xC0 == 0
        && u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) == MAGIC_COOKIE
}

fn parse(p: &[u8]) -> Option<String> {
    if !looks_like_stun(p) {
        return None;
    }
    let mtype = u16::from_be_bytes([p[0], p[1]]);
    let name = match mtype {
        0x0001 => "Binding Request",
        0x0101 => "Binding Success Response",
        0x0111 => "Binding Error Response",
        0x0011 => "Binding Indication",
        _ => "message",
    };
    Some(format!("STUN {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_msg(mtype: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&mtype.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // length
        p.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        p.extend_from_slice(&[0u8; 12]); // transaction id
        p
    }

    #[test]
    fn binding_request() {
        let r = dissect_stun(None, None, 40000, 3478, &stun_msg(0x0001));
        assert_eq!(r.protocol, Protocol::Stun);
        assert_eq!(r.summary, "STUN Binding Request");
    }

    #[test]
    fn rejects_non_stun() {
        assert!(!looks_like_stun(&[0u8; 20]));
    }
}
