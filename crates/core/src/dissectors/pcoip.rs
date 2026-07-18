// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PCoIP message (UDP/TCP 4172) — Teradici/VMware Horizon's remote
/// desktop display protocol. The payload is encrypted, so it's recognised by
/// its well-known port.
pub fn dissect_pcoip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pcoip,
        summary: format!("PCoIP remote display ({} bytes)", payload.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        let r = dissect_pcoip(None, None, 50000, 4172, &[0u8; 32]);
        assert_eq!(r.protocol, Protocol::Pcoip);
        assert!(
            r.summary.starts_with("PCoIP remote display"),
            "{}",
            r.summary
        );
    }
}
