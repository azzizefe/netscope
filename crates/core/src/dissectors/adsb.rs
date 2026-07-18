// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check: a Beast frame starts with the 0x1A escape and a type
/// character. Port 30005 is in the ephemeral range, so require the magic.
pub fn looks_like_adsb(p: &[u8]) -> bool {
    p.len() >= 2 && p[0] == 0x1A && matches!(p[1], b'1'..=b'4')
}

/// Dissect an ADS-B Beast stream (TCP 30005) — the framing dump1090 and
/// friends use to publish decoded aircraft transponder messages. Each frame
/// starts with the escape byte 0x1A and a type character.
pub fn dissect_adsb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.first() == Some(&0x1A) {
        let name = match payload.get(1) {
            Some(b'1') => "Mode A/C",
            Some(b'2') => "Mode S short",
            Some(b'3') => "Mode S long (ADS-B)",
            Some(b'4') => "status",
            _ => "frame",
        };
        format!("ADS-B Beast — {name}")
    } else {
        format!("ADS-B stream ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Adsb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_s_long() {
        let r = dissect_adsb(None, None, 30005, 40000, &[0x1A, b'3', 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Adsb);
        assert!(r.summary.contains("Mode S long"), "{}", r.summary);
    }
}
