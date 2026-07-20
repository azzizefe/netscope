// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

const ETHERTYPE_IPV6: u16 = 0x86DD;

/// The origin indicator is a fixed eight bytes: the marker, then an obfuscated
/// port and address (RFC 4380 §5.1.1).
const ORIGIN_INDICATOR: usize = 8;

/// Find the IPv6 packet, stepping over the indicator headers that may precede
/// it.
///
/// An authentication indicator is variable-length — it declares the size of the
/// client identifier and the authentication value it carries — so its length
/// has to be read rather than assumed.
fn inner_ipv6(payload: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    // At most one of each indicator can appear, so two steps is the maximum.
    for _ in 0..2 {
        match (payload.get(at), payload.get(at + 1)) {
            (Some(&b), _) if b >> 4 == 6 => return payload.get(at..),
            (Some(0x00), Some(0x00)) => {
                let id_len = *payload.get(at + 2)? as usize;
                let auth_len = *payload.get(at + 3)? as usize;
                // marker(2) + lengths(2) + the two values + nonce(8) + confirm(1)
                at += 4 + id_len + auth_len + 9;
            }
            (Some(0x00), Some(0x01)) => at += ORIGIN_INDICATOR,
            _ => return None,
        }
    }
    match payload.get(at) {
        Some(&b) if b >> 4 == 6 => payload.get(at..),
        _ => None,
    }
}

/// Dissect a Teredo packet (UDP 3544) — a transition tech that tunnels IPv6
/// through IPv4 NATs. The payload is either an IPv6 packet or a small
/// indicator header (RFC 4380).
pub fn dissect_teredo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // The point of a Teredo packet is the IPv6 packet inside it, so unwrap it
    // and report what is really being carried. The indicator headers come
    // first when present and have to be stepped over to find it.
    if let Some(inner) = inner_ipv6(payload) {
        let mut r = super::dispatch_l3(ETHERTYPE_IPV6, inner, 0);
        r.summary = format!("Teredo · {}", r.summary);
        return r;
    }

    let summary = match payload.first() {
        Some(0x00) => match payload.get(1) {
            Some(0x00) => "Teredo authentication indicator".to_string(),
            Some(0x01) => "Teredo origin indicator".to_string(),
            _ => "Teredo indicator".to_string(),
        },
        _ => format!("Teredo ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Teredo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv6 packet carrying a DNS query, so a passing test proves the inner
    /// packet was really dissected rather than merely detected.
    fn ipv6_dns() -> Vec<u8> {
        let dns = crate::dissectors::test_helpers::build_dns_query("example.com", 0x1234);
        let udp_len = 8 + dns.len();
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ip.push(17); // next header: UDP
        ip.push(64);
        ip.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip.extend_from_slice(&40000u16.to_be_bytes());
        ip.extend_from_slice(&53u16.to_be_bytes());
        ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00]);
        ip.extend_from_slice(&dns);
        ip
    }

    /// The tunnel is a note; the packet inside is what the reader wants.
    #[test]
    fn tunnelled_ipv6_is_unwrapped() {
        let r = dissect_teredo(None, None, 3544, 40000, &ipv6_dns());
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "Teredo · DNS Query — example.com");
    }

    /// An origin indicator is a fixed eight bytes in front of the packet.
    #[test]
    fn an_origin_indicator_is_stepped_over() {
        let mut p = vec![0x00, 0x01];
        p.extend_from_slice(&[0u8; 6]); // obfuscated port and address
        p.extend_from_slice(&ipv6_dns());
        let r = dissect_teredo(None, None, 3544, 40000, &p);
        assert_eq!(r.protocol, Protocol::Dns);
    }

    /// An authentication indicator is variable-length, so its size has to be
    /// read from the header rather than assumed.
    #[test]
    fn a_variable_length_authentication_indicator_is_stepped_over() {
        let (id_len, auth_len) = (4usize, 8usize);
        let mut p = vec![0x00, 0x00, id_len as u8, auth_len as u8];
        p.extend_from_slice(&vec![0xAA; id_len + auth_len]);
        p.extend_from_slice(&[0u8; 8]); // nonce
        p.push(0); // confirmation byte
        p.extend_from_slice(&ipv6_dns());
        let r = dissect_teredo(None, None, 3544, 40000, &p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "Teredo · DNS Query — example.com");
    }

    /// An indicator with nothing after it is still worth naming.
    #[test]
    fn a_bare_indicator_is_named() {
        let r = dissect_teredo(None, None, 3544, 1, &[0x00, 0x01, 0, 0]);
        assert_eq!(r.summary, "Teredo origin indicator");
    }

    #[test]
    fn a_foreign_payload_is_reported_by_size() {
        let r = dissect_teredo(None, None, 3544, 1, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(r.summary, "Teredo (3 bytes)");
    }
}
