// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RIPng — RIP for IPv6 (RFC 2080, UDP 521).
//!
//! RIPng keeps RIP's shape — periodic full-table broadcasts, a hop count, and
//! a maximum diameter of fifteen — but shares almost none of its wire format
//! with RIPv2. There is no address family field and no per-route
//! authentication; each route is a flat twenty-byte entry holding an IPv6
//! prefix, its length and its metric.
//!
//! The metric is what to read. Sixteen means *infinity*: the sender is
//! announcing that the destination is unreachable through it. That is how RIP
//! withdraws a route, and a table full of sixteens is a network in the middle
//! of reconverging — or, if it stays that way, one that has partitioned and
//! settled.
//!
//! The count-to-infinity that hop limit exists to bound is visible here too. A
//! prefix whose metric climbs by one in each successive announcement is a
//! routing loop being slowly discovered, and it will keep climbing until it
//! reaches sixteen and the route is finally dropped.

use std::net::{IpAddr, Ipv6Addr};

use crate::models::Protocol;

use super::DissectedResult;

/// Command, version and two reserved bytes.
const HEADER_LEN: usize = 4;
/// Prefix (16), route tag (2), prefix length (1), metric (1).
const ENTRY_LEN: usize = 20;

/// The metric that means "not reachable through me".
const METRIC_INFINITY: u8 = 16;
/// A metric of 0xFF marks the entry as a next-hop announcement rather than a
/// route — the address applies to the entries that follow it.
const METRIC_NEXT_HOP: u8 = 0xFF;

/// Format an IPv6 prefix the way an operator writes it.
fn prefix(bytes: &[u8], length: u8) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    format!("{}/{length}", Ipv6Addr::from(octets))
}

/// Dissect a RIPng message.
pub fn dissect_ripng(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ripng,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "RIPng".to_string();
    };
    let command = match head[0] {
        1 => "Request",
        2 => "Response",
        other => return format!("RIPng (command {other})"),
    };

    let entries: Vec<&[u8]> = payload[HEADER_LEN..].chunks_exact(ENTRY_LEN).collect();
    if entries.is_empty() {
        return format!("RIPng {command}");
    }

    // A withdrawal is the news. Report the first one rather than the first
    // route, because an announcement that a prefix has become unreachable is
    // what explains traffic that stopped.
    let withdrawn = entries
        .iter()
        .find(|e| e[19] == METRIC_INFINITY)
        .map(|e| prefix(&e[..16], e[18]));
    if let Some(gone) = withdrawn {
        let others = entries.len() - 1;
        return match others {
            0 => format!("RIPng {command} — {gone} unreachable"),
            n => format!("RIPng {command} — {gone} unreachable (+{n} routes)"),
        };
    }

    // Next-hop entries are not routes and would otherwise be reported as a
    // prefix with an absurd metric.
    let first = entries
        .iter()
        .find(|e| e[19] != METRIC_NEXT_HOP)
        .map(|e| (prefix(&e[..16], e[18]), e[19]));
    match (first, entries.len()) {
        (Some((route, metric)), 1) => format!("RIPng {command} — {route} metric {metric}"),
        (Some((route, metric)), n) => {
            format!(
                "RIPng {command} — {route} metric {metric} (+{} routes)",
                n - 1
            )
        }
        (None, n) => format!("RIPng {command} — {n} entries"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a RIPng message from (prefix byte, prefix length, metric) triples.
    fn message(command: u8, routes: &[(u8, u8, u8)]) -> Vec<u8> {
        let mut p = vec![command, 1, 0, 0];
        for &(lead, length, metric) in routes {
            let mut octets = [0u8; 16];
            octets[0] = 0x20;
            octets[1] = 0x01;
            octets[2] = lead;
            p.extend_from_slice(&octets);
            p.extend_from_slice(&[0, 0]); // route tag
            p.push(length);
            p.push(metric);
        }
        p
    }

    /// The reason this dissector exists: metric sixteen is a withdrawal, and
    /// it is what explains traffic that stopped reaching a prefix.
    #[test]
    fn an_unreachable_route_is_spelled_out() {
        let r = dissect_ripng(
            None,
            None,
            521,
            521,
            &message(2, &[(0xDB, 32, METRIC_INFINITY)]),
        );
        assert_eq!(r.protocol, Protocol::Ripng);
        assert_eq!(r.summary, "RIPng Response — 2001:db00::/32 unreachable");
    }

    /// A withdrawal buried among ordinary routes is still the news.
    #[test]
    fn a_withdrawal_is_reported_ahead_of_reachable_routes() {
        let p = message(
            2,
            &[(0x0A, 64, 3), (0xDB, 32, METRIC_INFINITY), (0x0C, 48, 5)],
        );
        let summary = describe(&p);
        assert!(summary.contains("2001:db00::/32 unreachable"), "{summary}");
        assert!(summary.contains("(+2 routes)"), "{summary}");
    }

    /// An ordinary announcement carries the hop count, which is what climbs
    /// during a count-to-infinity.
    #[test]
    fn a_reachable_route_reports_its_metric() {
        assert_eq!(
            describe(&message(2, &[(0x0A, 64, 3)])),
            "RIPng Response — 2001:a00::/64 metric 3"
        );
    }

    /// A next-hop entry is not a route. Reporting it as one would show a
    /// prefix with a metric of 255.
    #[test]
    fn a_next_hop_entry_is_not_reported_as_a_route() {
        let p = message(2, &[(0xFE, 0, METRIC_NEXT_HOP), (0x0A, 64, 3)]);
        let summary = describe(&p);
        assert!(summary.contains("metric 3"), "{summary}");
        assert!(!summary.contains("255"), "{summary}");
    }

    #[test]
    fn requests_and_responses_are_distinguished() {
        assert!(describe(&message(1, &[])).starts_with("RIPng Request"));
        assert!(describe(&message(2, &[])).starts_with("RIPng Response"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "RIPng");
        assert_eq!(describe(&[2, 1, 0]), "RIPng");
        assert_eq!(describe(&[2, 1, 0, 0]), "RIPng Response");
        // A partial entry is not a route, and is not counted as one.
        assert_eq!(describe(&[2, 1, 0, 0, 0x20, 0x01]), "RIPng Response");
        assert_eq!(describe(&[9, 1, 0, 0]), "RIPng (command 9)");
    }
}
