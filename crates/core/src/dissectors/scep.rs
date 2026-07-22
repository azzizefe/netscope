// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SCEP (Simple Certificate Enrollment Protocol — RFC 8894) message.
pub fn dissect_scep(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SCEP ({})", super::bytes(0u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        if text.contains("operation=PKIOperation") {
            "SCEP PKIOperation (Certificate Request/Response)".to_string()
        } else if text.contains("operation=GetCACert") {
            "SCEP GetCACert Request".to_string()
        } else if text.contains("operation=GetCACaps") {
            "SCEP GetCACaps Request".to_string()
        } else {
            format!("SCEP Enrollment Message ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Scep,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scep_get_ca_cert() {
        let payload = b"GET /cgi-bin/pkiclient.exe?operation=GetCACert HTTP/1.1\r\n";
        let res = dissect_scep(None, None, 80, 80, payload);
        assert_eq!(res.protocol, Protocol::Scep);
        assert!(res.summary.contains("GetCACert Request"));
    }

    #[test]
    fn test_scep_empty_payload() {
        let payload = vec![];
        let res = dissect_scep(None, None, 80, 80, &payload);
        assert_eq!(res.protocol, Protocol::Scep);
        assert!(res.summary.contains("SCEP (0 bytes)"));
    }
}
