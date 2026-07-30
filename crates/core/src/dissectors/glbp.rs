// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GLBP message (UDP 3222) — Cisco's gateway load-balancing
/// redundancy protocol. After the 12-byte header the first TLV type names the
/// message (Hello / Request-Response).
pub fn dissect_glbp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let name = match payload.get(12) {
        Some(1) => "Hello",
        Some(2) => "Request/Response",
        Some(3) => "Auth",
        _ => "advertisement",
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Glbp,
        summary: format!("GLBP {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello() {
        let mut p = vec![0u8; 12];
        p.push(1); // TLV type 1 (Hello)
        let r = dissect_glbp(None, None, 3222, 3222, &p);
        assert_eq!(r.protocol, Protocol::Glbp);
        assert_eq!(r.summary, "GLBP Hello");
    }
}
