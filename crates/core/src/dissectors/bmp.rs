// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BMP message (TCP 11019) — BGP Monitoring Protocol, how a router
/// streams its BGP state and route updates to a collector. Byte 0 is the
/// version (3) and byte 5 the message type (RFC 7854).
pub fn dissect_bmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 && payload[0] == 3 {
        let name = match payload[5] {
            0 => "Route Monitoring",
            1 => "Statistics Report",
            2 => "Peer Down",
            3 => "Peer Up",
            4 => "Initiation",
            5 => "Termination",
            6 => "Route Mirroring",
            _ => "message",
        };
        format!("BMP {name}")
    } else {
        format!("BMP ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_up() {
        // version 3, 4-byte length, type 3 (Peer Up).
        let r = dissect_bmp(None, None, 40000, 11019, &[3, 0, 0, 0, 40, 3]);
        assert_eq!(r.protocol, Protocol::Bmp);
        assert_eq!(r.summary, "BMP Peer Up");
    }
}
