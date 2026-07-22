// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an EST (Enrollment over Secure Transport — RFC 7030) message over HTTPS.
pub fn dissect_est(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("EST ({})", super::bytes(0u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        if text.contains("/.well-known/est/simpleenroll") {
            "EST simpleenroll (Certificate Enrollment)".to_string()
        } else if text.contains("/.well-known/est/simplereenroll") {
            "EST simplereenroll (Certificate Renewal)".to_string()
        } else if text.contains("/.well-known/est/cacerts") {
            "EST cacerts (Get CA Certificates)".to_string()
        } else {
            format!("EST Enrollment Message ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Est,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_est_simpleenroll() {
        let payload = b"POST /.well-known/est/simpleenroll HTTP/1.1\r\n";
        let res = dissect_est(None, None, 443, 443, payload);
        assert_eq!(res.protocol, Protocol::Est);
        assert!(res.summary.contains("simpleenroll"));
    }

    #[test]
    fn test_est_empty_payload() {
        let payload = vec![];
        let res = dissect_est(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Est);
        assert!(res.summary.contains("EST (0 bytes)"));
    }
}
