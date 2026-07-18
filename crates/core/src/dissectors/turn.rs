// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a TURN ChannelData message: the first two bytes are a
/// channel number in 0x4000..=0x7FFF, followed by a length that matches the
/// rest of the datagram. STUN messages start with 00 in the top two bits, so
/// the ranges never overlap (RFC 8656).
pub fn looks_like_turn(p: &[u8]) -> bool {
    if p.len() < 4 {
        return false;
    }
    let channel = u16::from_be_bytes([p[0], p[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return false;
    }
    // Require the declared length to fit the datagram (padding may follow).
    let len = u16::from_be_bytes([p[2], p[3]]) as usize;
    len > 0 && len <= p.len() - 4
}

/// Dissect a TURN ChannelData message — relayed media for a WebRTC or VoIP
/// call that couldn't traverse NAT directly. The channel number identifies the
/// peer the relay forwards to.
pub fn dissect_turn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let channel = u16::from_be_bytes([payload[0], payload[1]]);
    let len = u16::from_be_bytes([payload[2], payload[3]]);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Turn,
        summary: format!("TURN relayed data — channel 0x{channel:04x}, {len} bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_data() {
        let mut p = 0x4001u16.to_be_bytes().to_vec();
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 8]);
        assert!(looks_like_turn(&p));
        let r = dissect_turn(None, None, 50000, 3478, &p);
        assert_eq!(r.protocol, Protocol::Turn);
        assert!(r.summary.contains("channel 0x4001"), "{}", r.summary);
    }

    #[test]
    fn stun_is_not_channel_data() {
        // A STUN binding request: type 0x0001, so the top bits are clear.
        let p = [0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42];
        assert!(!looks_like_turn(&p));
    }
}
