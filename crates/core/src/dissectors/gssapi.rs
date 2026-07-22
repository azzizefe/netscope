// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GSSAPI / SPNEGO (RFC 2743 / RFC 4178) security token.
pub fn dissect_gssapi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("GSSAPI ({})", super::bytes(payload.len() as u64))
    } else {
        let is_spnego = payload.windows(6).any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
        if is_spnego {
            "GSSAPI / SPNEGO Negotiation Token".to_string()
        } else {
            format!("GSSAPI Security Token ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gssapi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gssapi_spnego() {
        // SPNEGO OID = 1.3.6.1.5.5.2 (0x2b 0x06 0x01 0x05 0x05 0x02)
        let payload = vec![0x60, 0x10, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        let res = dissect_gssapi(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Gssapi);
        assert!(res.summary.contains("SPNEGO Negotiation Token"));
    }

    #[test]
    fn test_gssapi_short_payload() {
        let payload = vec![0x60, 0x01];
        let res = dissect_gssapi(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Gssapi);
        assert!(res.summary.contains("GSSAPI (2 bytes)"));
    }
}
