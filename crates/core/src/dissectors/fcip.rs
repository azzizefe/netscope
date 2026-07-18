// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an FCIP frame (TCP 3225) — Fibre Channel over IP, which bridges two
/// storage-area networks across a WAN. The encapsulation header repeats the
/// protocol and version, then their ones-complement, which is what makes the
/// framing recognisable (RFC 3821).
pub fn dissect_fcip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4
        && payload[0] == 0x01
        && payload[2] == !payload[0]
        && payload[3] == !payload[1]
    {
        "FCIP — Fibre Channel frame over IP".to_string()
    } else {
        format!("FCIP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fcip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulated_frame() {
        // protocol 1, version 1, then their ones-complements.
        let r = dissect_fcip(None, None, 40000, 3225, &[0x01, 0x01, 0xFE, 0xFE]);
        assert_eq!(r.protocol, Protocol::Fcip);
        assert!(r.summary.contains("Fibre Channel"), "{}", r.summary);
    }
}
