// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect DNS over QUIC (DoQ) Protocol (UDP 853).
pub fn dissect_dns_over_quic(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("DNS over QUIC (DoQ) ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DnsOverQuic,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doq_test() {
        let r = dissect_dns_over_quic(None, None, 40000, 853, b"\xc0\x00\x00\x01doq");
        assert_eq!(r.protocol, Protocol::DnsOverQuic);
    }
}
