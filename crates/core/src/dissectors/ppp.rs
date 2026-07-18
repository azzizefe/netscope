// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect the PPP payload of a PPPoE session. The 2-byte protocol field names
/// the encapsulated layer; the authentication protocols get their own
/// dissectors, since PAP in particular carries a cleartext password.
pub fn dissect_ppp(payload: &[u8]) -> DissectedResult {
    if payload.len() < 2 {
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Ppp,
            summary: "PPP (truncated)".into(),
        };
    }
    let proto = u16::from_be_bytes([payload[0], payload[1]]);
    let body = &payload[2..];
    match proto {
        0xC023 => return super::pap::dissect_pap(body),
        0xC223 => return super::chap::dissect_chap(body),
        _ => {}
    }
    let name = match proto {
        0x0021 => "IPv4",
        0x0057 => "IPv6",
        0xC021 => "LCP (link control)",
        0x8021 => "IPCP (IPv4 config)",
        0x8057 => "IPv6CP",
        0xC025 => "LQR (link quality)",
        0x80FD => "CCP (compression)",
        0x8053 => "ECP (encryption)",
        _ => "payload",
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ppp,
        summary: format!("PPP — {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcp() {
        let r = dissect_ppp(&[0xC0, 0x21, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Ppp);
        assert!(r.summary.contains("LCP"), "{}", r.summary);
    }

    #[test]
    fn hands_pap_to_its_own_dissector() {
        let r = dissect_ppp(&[0xC0, 0x23, 0x01, 0x01, 0x00, 0x09, 0x03, b'a', b'b', b'c']);
        assert_eq!(r.protocol, Protocol::Pap);
    }
}
