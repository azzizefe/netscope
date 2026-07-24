// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect a ISO 8583 Financial Transaction packet.
pub fn dissect_iso8583(
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
        protocol: Protocol::Iso8583,
        summary: format!("ISO 8583 Financial Transaction ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso8583() {
        let r = dissect_iso8583(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::Iso8583);
    }
}
