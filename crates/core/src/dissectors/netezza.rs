// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect IBM Netezza wire protocol (TCP 5480).
pub fn dissect_netezza(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Netezza Wire Protocol ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Netezza,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netezza_test() {
        let r = dissect_netezza(None, None, 40000, 5480, b"\x00\x00\x00\x08");
        assert_eq!(r.protocol, Protocol::Netezza);
    }
}
