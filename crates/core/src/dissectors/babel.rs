// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Babel message (UDP 6696) — a loop-avoiding distance-vector routing
/// protocol popular in mesh/community networks. Byte 0 is the magic (42) and
/// byte 1 the version (RFC 8966).
pub fn dissect_babel(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 && payload[0] == 42 {
        format!("Babel routing update (v{})", payload[1])
    } else {
        format!("Babel ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Babel,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update() {
        // magic 42, version 2.
        let r = dissect_babel(None, None, 6696, 6696, &[42, 2, 0x00, 0x10]);
        assert_eq!(r.protocol, Protocol::Babel);
        assert_eq!(r.summary, "Babel routing update (v2)");
    }
}
