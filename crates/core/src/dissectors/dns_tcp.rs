// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DNS over TCP (RFC 1035 §4.2.2).
//!
//! DNS is usually thought of as a UDP protocol, but three things push it onto
//! TCP: a response too large for a datagram, a client that was told to retry
//! over TCP, and a zone transfer. The last of those is the reason this needs
//! its own path rather than being left as unrecognised TCP — an AXFR is one
//! host asking another for the *entire contents* of a DNS zone, which is
//! either routine replication between name servers or someone helping
//! themselves to a map of the network.
//!
//! The framing differs from the UDP form: every message is preceded by its
//! length in two bytes, because TCP has no message boundaries of its own.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The two-byte length that precedes every message.
const LENGTH_PREFIX: usize = 2;
/// The DNS header itself, which the length must be able to cover.
const DNS_HEADER: usize = 12;

/// Query types that only appear over TCP, and are worth calling out.
const QTYPE_AXFR: u16 = 252;
const QTYPE_IXFR: u16 = 251;

/// Read the query type from the question section, if there is one.
///
/// The question begins after the header with a name in length-prefixed labels,
/// then the type. Walking the labels is the only way to reach it, since names
/// vary in length.
fn query_type(message: &[u8]) -> Option<u16> {
    let questions = u16::from_be_bytes([*message.get(4)?, *message.get(5)?]);
    if questions == 0 {
        return None;
    }
    let mut at = DNS_HEADER;
    // A name is a run of labels ending in a zero byte. A label longer than 63
    // bytes is a compression pointer, which cannot appear in a question.
    loop {
        let len = *message.get(at)? as usize;
        if len == 0 {
            at += 1;
            break;
        }
        if len > 63 {
            return None;
        }
        at += len + 1;
    }
    Some(u16::from_be_bytes([
        *message.get(at)?,
        *message.get(at + 1)?,
    ]))
}

/// Dissect a DNS message carried over TCP (port 53).
pub fn dissect_dns_tcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dns,
        summary,
    };

    let Some(length) = payload
        .get(..LENGTH_PREFIX)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    else {
        return fallback(format!(
            "DNS over TCP ({})",
            super::bytes(payload.len() as u64)
        ));
    };
    if length < DNS_HEADER {
        return fallback(format!(
            "DNS over TCP ({})",
            super::bytes(payload.len() as u64)
        ));
    }
    // A message split across segments is normal; take what is present rather
    // than refusing to decode until the whole thing has arrived.
    let end = (LENGTH_PREFIX + length).min(payload.len());
    let Some(message) = payload.get(LENGTH_PREFIX..end) else {
        return fallback(format!(
            "DNS over TCP ({})",
            super::bytes(payload.len() as u64)
        ));
    };

    // A zone transfer is worth naming on its own: it is either replication
    // between name servers or someone dumping the zone.
    match query_type(message) {
        Some(QTYPE_AXFR) => {
            return fallback("DNS zone transfer request (AXFR — full zone)".to_string())
        }
        Some(QTYPE_IXFR) => {
            return fallback("DNS zone transfer request (IXFR — changes only)".to_string())
        }
        _ => {}
    }

    let mut inner = super::dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, message);
    inner.summary = format!("{} (over TCP)", inner.summary);
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a DNS message in the length prefix TCP requires.
    fn framed(message: &[u8]) -> Vec<u8> {
        let mut p = (message.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(message);
        p
    }

    /// Build a query for `domain` with the given type.
    fn query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut p = 0x1234u16.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x00, 0x00]); // flags
        p.extend_from_slice(&1u16.to_be_bytes()); // one question
        p.extend_from_slice(&[0u8; 6]); // no answers, authority or additional
        for part in domain.split('.') {
            p.push(part.len() as u8);
            p.extend_from_slice(part.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // class IN
        p
    }

    /// The reason this needs its own path: a full zone transfer is either
    /// routine replication or someone taking a copy of the network's map.
    #[test]
    fn a_full_zone_transfer_is_named() {
        let r = dissect_dns_tcp(
            None,
            None,
            40000,
            53,
            &framed(&query("example.com", QTYPE_AXFR)),
        );
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "DNS zone transfer request (AXFR — full zone)");
    }

    /// An incremental transfer asks only for what changed, which is the normal
    /// replication case and reads differently from a full dump.
    #[test]
    fn an_incremental_transfer_is_distinguished() {
        let r = dissect_dns_tcp(
            None,
            None,
            40000,
            53,
            &framed(&query("example.com", QTYPE_IXFR)),
        );
        assert_eq!(r.summary, "DNS zone transfer request (IXFR — changes only)");
    }

    /// An ordinary query over TCP is still a query; only the framing differs.
    #[test]
    fn an_ordinary_query_decodes_normally() {
        let r = dissect_dns_tcp(None, None, 40000, 53, &framed(&query("example.com", 1)));
        assert_eq!(r.summary, "DNS Query — example.com (over TCP)");
    }

    /// The length prefix is the whole difference from the UDP form; skipping
    /// it would feed the parser two bytes of length as if they were a
    /// transaction id.
    #[test]
    fn the_length_prefix_is_stripped() {
        let message = query("example.com", 1);
        let with_prefix = dissect_dns_tcp(None, None, 1, 53, &framed(&message));
        assert!(with_prefix.summary.contains("example.com"));
    }

    /// A long response arrives across several segments, so a message shorter
    /// than its declared length must still decode as far as it goes.
    #[test]
    fn a_message_split_across_segments_still_decodes() {
        let message = query("example.com", 1);
        let mut p = 4096u16.to_be_bytes().to_vec(); // claims far more to come
        p.extend_from_slice(&message);
        let r = dissect_dns_tcp(None, None, 1, 53, &p);
        assert!(r.summary.contains("example.com"), "got {}", r.summary);
    }

    /// The question name is variable-length, so the type is not at a fixed
    /// offset — a longer name has to be walked past.
    #[test]
    fn the_query_type_is_found_past_a_long_name() {
        let long = "a-very-long-subdomain.under.some.other.domain.example.com";
        let r = dissect_dns_tcp(None, None, 1, 53, &framed(&query(long, QTYPE_AXFR)));
        assert_eq!(r.summary, "DNS zone transfer request (AXFR — full zone)");
    }

    #[test]
    fn truncated_and_implausible_lengths_do_not_panic() {
        assert_eq!(
            dissect_dns_tcp(None, None, 1, 53, &[0x00]).summary,
            "DNS over TCP (1 byte)"
        );
        // A declared length too small to hold a DNS header.
        assert_eq!(
            dissect_dns_tcp(None, None, 1, 53, &[0x00, 0x04, 0, 0, 0, 0]).summary,
            "DNS over TCP (6 bytes)"
        );
    }
}
