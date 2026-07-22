// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect NETCONF Network Configuration Protocol (TCP 830).
pub fn dissect_netconf(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"<?xml") || payload.starts_with(b"<hello") || payload.starts_with(b"<rpc") {
        "NETCONF XML message".to_string()
    } else {
        format!("NETCONF ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Netconf,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netconf_test() {
        let r = dissect_netconf(None, None, 40000, 830, b"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">");
        assert_eq!(r.protocol, Protocol::Netconf);
        assert!(r.summary.contains("XML message"));
    }
}
