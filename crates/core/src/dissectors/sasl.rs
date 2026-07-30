// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SASL (Simple Authentication and Security Layer — RFC 4422) exchange.
pub fn dissect_sasl(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SASL ({})", super::bytes(0u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        let mech = if text.contains("PLAIN") {
            "PLAIN"
        } else if text.contains("GSSAPI") {
            "GSSAPI"
        } else if text.contains("DIGEST-MD5") {
            "DIGEST-MD5"
        } else if text.contains("EXTERNAL") {
            "EXTERNAL"
        } else {
            "Exchange"
        };
        format!("SASL Auth — Mechanism {mech}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sasl,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sasl_plain() {
        let payload = b"AUTH PLAIN \x00user\x00pass";
        let res = dissect_sasl(None, None, 0, 0, payload);
        assert_eq!(res.protocol, Protocol::Sasl);
        assert!(res.summary.contains("PLAIN"));
    }

    #[test]
    fn test_sasl_empty_payload() {
        let payload = vec![];
        let res = dissect_sasl(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Sasl);
        assert!(res.summary.contains("SASL (0 bytes)"));
    }
}
