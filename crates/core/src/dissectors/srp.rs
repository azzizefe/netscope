// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Secure Remote Password (SRP — RFC 2945 / RFC 5054) authentication exchange.
pub fn dissect_srp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SRP ({})", super::bytes(0u64))
    } else {
        format!("SRP (Secure Remote Password) Handshake ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Srp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srp_handshake() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let res = dissect_srp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Srp);
        assert!(res.summary.contains("Secure Remote Password"));
    }

    #[test]
    fn test_srp_empty_payload() {
        let payload = vec![];
        let res = dissect_srp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Srp);
        assert!(res.summary.contains("SRP (0 bytes)"));
    }
}
