// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an ERSPAN header carried inside GRE — Encapsulated Remote SPAN,
/// which tunnels a switch's mirrored traffic to a remote analyser. That means
/// the payload is *someone else's* traffic, deliberately copied: worth knowing
/// when you see it. The version is the top nibble and the session id the low
/// 10 bits of the second half-word.
pub fn dissect_erspan(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = payload[0] >> 4;
        let session = u16::from_be_bytes([payload[2], payload[3]]) & 0x03FF;
        format!("ERSPAN v{version} — mirrored traffic, session {session}")
    } else {
        "ERSPAN (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Erspan,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_two_session() {
        // version 1 (type II), vlan, then session id 5 in the low 10 bits.
        let r = dissect_erspan(None, None, &[0x10, 0x00, 0x00, 0x05]);
        assert_eq!(r.protocol, Protocol::Erspan);
        assert!(r.summary.contains("session 5"), "{}", r.summary);
    }
}
