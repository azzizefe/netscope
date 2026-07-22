// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect DNSCrypt Encrypted DNS Protocol (UDP 443 / 5353).
pub fn dissect_dnscrypt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"r6fn:") || payload.len() >= 8 {
        "DNSCrypt query/response envelope".to_string()
    } else {
        format!("DNSCrypt ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dnscrypt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnscrypt_test() {
        let r = dissect_dnscrypt(None, None, 40000, 443, b"r6fn:1234567890123456");
        assert_eq!(r.protocol, Protocol::Dnscrypt);
        assert_eq!(r.summary, "DNSCrypt query/response envelope");
    }
}
