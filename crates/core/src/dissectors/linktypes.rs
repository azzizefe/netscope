// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Link-layer types that carry IP without an Ethernet header.
//!
//! Not every capture starts with a MAC address. Capturing on a loopback
//! interface, a VPN tunnel or a serial link produces frames with a different
//! shape — or with no link header at all — and parsing those as Ethernet reads
//! the first fourteen bytes of the IP packet as addresses, leaving everything
//! after it misaligned. The result is not an obvious failure but a screenful of
//! nonsense, which is worse.
//!
//! Loopback capture in particular is one of the most common things anyone does
//! with a packet analyser, so getting it right matters more than its obscurity
//! suggests.

use super::{dispatch_l3, DissectedResult};
use crate::models::Protocol;

/// EtherType values the callers below hand to the shared L3 dispatch.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// The BSD loopback header is a four-byte address family.
const LOOPBACK_HEADER: usize = 4;

/// Address family values seen in loopback captures. `AF_INET` is 2 everywhere,
/// but `AF_INET6` differs per operating system — 10 on Linux, 24 on OpenBSD,
/// 28 on FreeBSD, 30 on macOS — so all four are accepted.
fn address_family(af: u32) -> Option<u16> {
    match af {
        2 => Some(ETHERTYPE_IPV4),
        10 | 24 | 28 | 30 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

fn malformed(reason: &str) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown(reason.to_string()),
        summary: format!("Malformed packet ({reason})"),
    }
}

/// Dissect a BSD loopback frame (`DLT_NULL`).
///
/// The address family is written in the *host* byte order of the machine that
/// captured, which is almost always little-endian but is not guaranteed. Trying
/// one order and giving up would silently break captures moved between
/// architectures, so both are tried.
pub fn dissect_loopback(data: &[u8]) -> DissectedResult {
    let Some(head) = data.get(..LOOPBACK_HEADER) else {
        return malformed("truncated loopback header");
    };
    let le = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let be = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    match address_family(le).or_else(|| address_family(be)) {
        Some(ethertype) => dispatch_l3(ethertype, &data[LOOPBACK_HEADER..], 0),
        None => malformed("unrecognised loopback address family"),
    }
}

/// Dissect an OpenBSD loopback frame (`DLT_LOOP`), which is the same header in
/// network byte order rather than the host's.
pub fn dissect_loop(data: &[u8]) -> DissectedResult {
    let Some(head) = data.get(..LOOPBACK_HEADER) else {
        return malformed("truncated loopback header");
    };
    let af = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    match address_family(af) {
        Some(ethertype) => dispatch_l3(ethertype, &data[LOOPBACK_HEADER..], 0),
        None => malformed("unrecognised loopback address family"),
    }
}

/// Dissect a raw IP packet (`DLT_RAW`), as produced by tunnel interfaces and
/// most VPN clients. There is no link header at all — the version nibble of the
/// IP header is the only thing that says which protocol follows.
pub fn dissect_raw_ip(data: &[u8]) -> DissectedResult {
    match data.first().map(|b| b >> 4) {
        Some(4) => dispatch_l3(ETHERTYPE_IPV4, data, 0),
        Some(6) => dispatch_l3(ETHERTYPE_IPV6, data, 0),
        _ => malformed("raw capture is not an IP packet"),
    }
}

/// Dissect a capture declared as carrying only IPv4 (`DLT_IPV4`).
pub fn dissect_ipv4_only(data: &[u8]) -> DissectedResult {
    dispatch_l3(ETHERTYPE_IPV4, data, 0)
}

/// Dissect a capture declared as carrying only IPv6 (`DLT_IPV6`).
pub fn dissect_ipv6_only(data: &[u8]) -> DissectedResult {
    dispatch_l3(ETHERTYPE_IPV6, data, 0)
}

/// The Cisco HDLC header: address, control, then a two-byte protocol field that
/// holds an EtherType.
const HDLC_HEADER: usize = 4;

/// Dissect a Cisco HDLC frame (`DLT_C_HDLC`), the default encapsulation on
/// router serial links.
pub fn dissect_cisco_hdlc(data: &[u8]) -> DissectedResult {
    let Some(head) = data.get(..HDLC_HEADER) else {
        return malformed("truncated Cisco HDLC header");
    };
    let ethertype = u16::from_be_bytes([head[2], head[3]]);
    dispatch_l3(ethertype, &data[HDLC_HEADER..], 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4 packet carrying a real DNS query, so a passing test
    /// proves the whole chain ran — link header, IP, UDP and the application
    /// dissector — rather than only that the link header was skipped.
    fn ipv4_dns_query() -> Vec<u8> {
        let dns = crate::dissectors::test_helpers::build_dns_query("example.com", 0x1234);
        let udp_len = 8 + dns.len();

        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes()); // total length
        p.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 0x40, 17, 0x00, 0x00]);
        p.extend_from_slice(&[127, 0, 0, 1]);
        p.extend_from_slice(&[127, 0, 0, 1]);
        p.extend_from_slice(&40000u16.to_be_bytes()); // source port
        p.extend_from_slice(&53u16.to_be_bytes()); // destination port
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p.extend_from_slice(&dns);
        p
    }

    #[test]
    fn loopback_ipv4_reaches_the_application_layer() {
        let mut p = 2u32.to_le_bytes().to_vec(); // AF_INET, little-endian
        p.extend_from_slice(&ipv4_dns_query());
        let r = dissect_loopback(&p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "DNS Query — example.com");
        assert_eq!(r.dst_port, Some(53));
    }

    /// A capture taken on a big-endian machine writes the family the other way
    /// round; both have to work or moving a file breaks it.
    #[test]
    fn loopback_accepts_either_host_byte_order() {
        let mut le = 2u32.to_le_bytes().to_vec();
        le.extend_from_slice(&ipv4_dns_query());
        let mut be = 2u32.to_be_bytes().to_vec();
        be.extend_from_slice(&ipv4_dns_query());
        assert_eq!(dissect_loopback(&le).protocol, Protocol::Dns);
        assert_eq!(dissect_loopback(&be).protocol, Protocol::Dns);
    }

    /// The IPv6 family number differs per operating system, and a capture is
    /// often read on a different one than it was taken on.
    #[test]
    fn every_operating_systems_ipv6_family_is_accepted() {
        for af in [10u32, 24, 28, 30] {
            assert_eq!(
                address_family(af),
                Some(ETHERTYPE_IPV6),
                "AF {af} should be IPv6"
            );
        }
        assert_eq!(address_family(2), Some(ETHERTYPE_IPV4));
        assert_eq!(address_family(999), None);
    }

    #[test]
    fn raw_ip_needs_no_link_header() {
        let r = dissect_raw_ip(&ipv4_dns_query());
        assert_eq!(r.protocol, Protocol::Dns);
    }

    /// A raw capture that is not IP at all should say so rather than being
    /// decoded as whatever the first nibble happens to suggest.
    #[test]
    fn raw_non_ip_is_reported() {
        let r = dissect_raw_ip(&[0x77, 0x00, 0x00]);
        assert!(r.summary.contains("not an IP packet"));
        let r = dissect_raw_ip(&[]);
        assert!(r.summary.contains("not an IP packet"));
    }

    #[test]
    fn cisco_hdlc_reads_its_protocol_field() {
        let mut p = vec![0x0F, 0x00]; // address, control
        p.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
        p.extend_from_slice(&ipv4_dns_query());
        let r = dissect_cisco_hdlc(&p);
        assert_eq!(r.protocol, Protocol::Dns);
    }

    #[test]
    fn truncated_headers_do_not_panic() {
        assert!(dissect_loopback(&[0x02, 0x00])
            .summary
            .contains("truncated"));
        assert!(dissect_loop(&[0x00]).summary.contains("truncated"));
        assert!(dissect_cisco_hdlc(&[0x0F]).summary.contains("truncated"));
    }

    /// An address family we do not recognise is reported rather than guessed
    /// at, because guessing would produce a screenful of nonsense.
    #[test]
    fn unknown_address_family_is_reported() {
        let mut p = 999u32.to_le_bytes().to_vec();
        p.extend_from_slice(&ipv4_dns_query());
        assert!(dissect_loopback(&p)
            .summary
            .contains("unrecognised loopback address family"));
    }
}
