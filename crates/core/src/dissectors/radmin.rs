// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Radmin message (TCP 4899) — a Windows remote-control tool. The
/// session payload is encrypted, so it's recognised by its well-known port.
pub fn dissect_radmin(
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
        protocol: Protocol::Radmin,
        summary: format!(
            "Radmin remote control ({})",
            super::bytes(payload.len() as u64)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session() {
        let r = dissect_radmin(None, None, 40000, 4899, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Radmin);
        assert!(
            r.summary.starts_with("Radmin remote control"),
            "{}",
            r.summary
        );
    }
}
