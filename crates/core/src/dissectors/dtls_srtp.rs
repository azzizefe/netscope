// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DTLS-SRTP (RFC 5764 DTLS extension for SRTP keying) packet.
pub fn dissect_dtls_srtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 13 {
        format!("DTLS-SRTP ({})", super::bytes(payload.len() as u64))
    } else {
        let content_type = payload[0];
        let type_desc = match content_type {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake (use_srtp)",
            23 => "Application Data (SRTP Master Key)",
            _ => "Record",
        };
        format!("DTLS-SRTP Key Exchange — {type_desc}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DtlsSrtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_srtp_handshake() {
        let mut payload = vec![22, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100];
        payload.resize(30, 0);

        let res = dissect_dtls_srtp(None, None, 5004, 5004, &payload);
        assert_eq!(res.protocol, Protocol::DtlsSrtp);
        assert!(res.summary.contains("Handshake"));
    }

    #[test]
    fn test_dtls_srtp_short_payload() {
        let payload = vec![22, 254];
        let res = dissect_dtls_srtp(None, None, 5004, 5004, &payload);
        assert_eq!(res.protocol, Protocol::DtlsSrtp);
        assert!(res.summary.contains("DTLS-SRTP (2 bytes)"));
    }
}
