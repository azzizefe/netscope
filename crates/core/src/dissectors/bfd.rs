// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BFD control packet (UDP 3784) — a fast liveness check between
/// routers so failover happens in milliseconds. The high 3 bits of byte 0 are
/// the version; the high 2 bits of byte 1 are the session state (RFC 5880).
pub fn dissect_bfd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let version = payload[0] >> 5;
        let state = match payload[1] >> 6 {
            0 => "AdminDown",
            1 => "Down",
            2 => "Init",
            3 => "Up",
            _ => "?",
        };
        format!("BFDv{version} control — state {state}")
    } else {
        "BFD (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bfd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_up() {
        // version 1 (0x20), state Up (0xC0).
        let r = dissect_bfd(None, None, 49152, 3784, &[0x20, 0xC0, 0x03, 0x18]);
        assert_eq!(r.protocol, Protocol::Bfd);
        assert_eq!(r.summary, "BFDv1 control — state Up");
    }
}
