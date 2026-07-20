// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! NFLOG — the Linux firewall's own log stream (`DLT_NFLOG`).
//!
//! An iptables or nftables rule can hand a packet to a log group instead of, or
//! as well as, dropping it, and `tcpdump -i nflog:1` reads that group. What
//! makes it worth decoding rather than treating as raw IP is the prefix: the
//! string the rule author attached, usually naming the rule. So a capture can
//! say not only that a packet was blocked but *which rule* blocked it, which is
//! the question anyone debugging a firewall actually has.

use super::{dispatch_l3, DissectedResult};
use crate::models::Protocol;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Address family, version, then a resource id.
const HEADER: usize = 4;

/// Attribute types (`linux/netfilter/nfnetlink_log.h`). Only the two that carry
/// meaning for a reader are pulled out.
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;

/// A TLV header: length then type, each two bytes.
const TLV_HEADER: usize = 4;

/// An attribute longer than the buffer, or shorter than its own header, means
/// the byte order guess was wrong.
fn plausible(length: usize, remaining: usize) -> bool {
    length >= TLV_HEADER && length <= remaining
}

/// Walk the attribute list, returning the logged packet and the rule prefix.
///
/// The lengths and types are written in the *host* byte order of the machine
/// that captured, exactly as in a loopback capture, so both orders are tried
/// and the one that produces a self-consistent chain wins.
fn attributes(body: &[u8], little_endian: bool) -> Option<(Option<String>, Option<&[u8]>)> {
    let read = |b: &[u8], at: usize| -> Option<u16> {
        let pair = [*b.get(at)?, *b.get(at + 1)?];
        Some(if little_endian {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        })
    };

    let mut prefix = None;
    let mut payload = None;
    let mut at = 0usize;
    // Every attribute is at least four bytes, so the buffer bounds the walk.
    while at + TLV_HEADER <= body.len() {
        let length = read(body, at)? as usize;
        let kind = read(body, at + 2)?;
        if !plausible(length, body.len() - at) {
            // A chain that does not hold together means this byte order is the
            // wrong guess, so report nothing rather than half-read rubbish.
            return if prefix.is_some() || payload.is_some() {
                Some((prefix, payload))
            } else {
                None
            };
        }
        let value = body.get(at + TLV_HEADER..at + length)?;
        match kind {
            NFULA_PREFIX => {
                // The prefix is NUL-terminated.
                let text = value.split(|&b| b == 0).next().unwrap_or(value);
                if let Ok(s) = std::str::from_utf8(text) {
                    if !s.is_empty() {
                        prefix = Some(s.trim().to_string());
                    }
                }
            }
            NFULA_PAYLOAD => payload = Some(value),
            _ => {}
        }
        // Attributes are padded out to a four-byte boundary.
        at += length.div_ceil(4) * 4;
    }
    Some((prefix, payload))
}

/// Dissect a packet from a Linux netfilter log group.
pub fn dissect_nflog(data: &[u8]) -> DissectedResult {
    let malformed = |reason: &str| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown(reason.to_string()),
        summary: format!("Malformed packet ({reason})"),
    };

    let Some(head) = data.get(..HEADER) else {
        return malformed("truncated NFLOG header");
    };
    let ethertype = match head[0] {
        2 => ETHERTYPE_IPV4,
        10 => ETHERTYPE_IPV6,
        other => return malformed(&format!("NFLOG address family {other}")),
    };

    let body = &data[HEADER..];
    // Prefer whichever byte order yields a packet, since that is the stronger
    // evidence of having guessed right — but do not discard a parse that found
    // only a prefix, because a rule can log without attaching the packet.
    let little = attributes(body, true);
    let big = attributes(body, false);
    let (prefix, payload) = match (&little, &big) {
        (Some(l), _) if l.1.is_some() => little.unwrap(),
        (_, Some(b)) if b.1.is_some() => big.unwrap(),
        (Some(_), _) => little.unwrap(),
        (_, Some(_)) => big.unwrap(),
        _ => (None, None),
    };

    let Some(payload) = payload else {
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Nflog,
            summary: match prefix {
                Some(p) => format!("NFLOG [{p}] — no packet attached"),
                None => "NFLOG — no packet attached".to_string(),
            },
        };
    };

    let mut inner = dispatch_l3(ethertype, payload, 0);
    // The rule name is the fact a firewall debugger is after, so it goes first.
    inner.summary = match prefix {
        Some(p) => format!("NFLOG [{p}] · {}", inner.summary),
        None => format!("NFLOG · {}", inner.summary),
    };
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one attribute in the given byte order, padded as the format
    /// requires.
    fn attribute(kind: u16, value: &[u8], little_endian: bool) -> Vec<u8> {
        let length = (TLV_HEADER + value.len()) as u16;
        let mut p = if little_endian {
            let mut v = length.to_le_bytes().to_vec();
            v.extend_from_slice(&kind.to_le_bytes());
            v
        } else {
            let mut v = length.to_be_bytes().to_vec();
            v.extend_from_slice(&kind.to_be_bytes());
            v
        };
        p.extend_from_slice(value);
        while p.len() % 4 != 0 {
            p.push(0);
        }
        p
    }

    /// A minimal IPv4 packet carrying a DNS query.
    fn ipv4_dns() -> Vec<u8> {
        let dns = crate::dissectors::test_helpers::build_dns_query("example.com", 0x1234);
        let udp_len = 8 + dns.len();
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 0x40, 17, 0x00, 0x00]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&40000u16.to_be_bytes());
        ip.extend_from_slice(&53u16.to_be_bytes());
        ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00]);
        ip.extend_from_slice(&dns);
        ip
    }

    fn nflog(prefix: &str, little_endian: bool) -> Vec<u8> {
        let mut p = vec![2u8, 0]; // AF_INET, version 0
        p.extend_from_slice(&0u16.to_be_bytes()); // resource id
        let mut with_nul = prefix.as_bytes().to_vec();
        with_nul.push(0);
        p.extend_from_slice(&attribute(NFULA_PREFIX, &with_nul, little_endian));
        p.extend_from_slice(&attribute(NFULA_PAYLOAD, &ipv4_dns(), little_endian));
        p
    }

    /// The rule name is the whole reason to decode this rather than treat it as
    /// raw IP: it says which rule acted on the packet.
    #[test]
    fn the_rule_prefix_leads_the_summary() {
        let r = dissect_nflog(&nflog("DROP-INBOUND", true));
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "NFLOG [DROP-INBOUND] · DNS Query — example.com");
    }

    /// The attribute lengths are in the capturing host's byte order, so a file
    /// moved between architectures has to keep working.
    #[test]
    fn either_host_byte_order_is_read() {
        let le = dissect_nflog(&nflog("DROP", true));
        let be = dissect_nflog(&nflog("DROP", false));
        assert_eq!(le.summary, "NFLOG [DROP] · DNS Query — example.com");
        assert_eq!(be.summary, "NFLOG [DROP] · DNS Query — example.com");
    }

    /// A rule with no prefix still logs, and the packet is still the point.
    #[test]
    fn a_missing_prefix_does_not_hide_the_packet() {
        let mut p = vec![2u8, 0, 0, 0];
        p.extend_from_slice(&attribute(NFULA_PAYLOAD, &ipv4_dns(), true));
        let r = dissect_nflog(&p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "NFLOG · DNS Query — example.com");
    }

    #[test]
    fn ipv6_family_is_accepted() {
        let mut p = vec![10u8, 0, 0, 0]; // AF_INET6
        p.extend_from_slice(&attribute(NFULA_PREFIX, b"BLOCK\0", true));
        let r = dissect_nflog(&p);
        assert_eq!(r.summary, "NFLOG [BLOCK] — no packet attached");
    }

    #[test]
    fn unknown_family_is_reported() {
        let r = dissect_nflog(&[99, 0, 0, 0]);
        assert!(r.summary.contains("NFLOG address family 99"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(dissect_nflog(&[2, 0]).summary.contains("truncated"));
        assert!(dissect_nflog(&[]).summary.contains("truncated"));
    }
}
