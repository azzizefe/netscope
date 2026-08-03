// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

pub fn dissect_icmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
    is_v6: bool,
) -> DissectedResult {
    // RPL is a whole routing protocol carried as one ICMPv6 type; what it
    // says about the mesh is the truer label than "ICMP message" would be.
    if is_v6 && payload.first() == Some(&super::rpl::ICMPV6_TYPE) {
        return super::rpl::dissect_rpl(src_ip, dst_ip, payload);
    }

    let summary = match payload.first() {
        Some(&icmp_type) => {
            // The code byte is half the message. Type 11 (v4) and type 3 (v6)
            // are both "Time Exceeded", and code 1 means the *fragment
            // reassembly* timer ran out rather than the hop count — a
            // different event with a different cause, which this reported as a
            // TTL expiry either way.
            let code = payload.get(1).copied().unwrap_or(0);
            if is_v6 {
                describe_icmpv6(icmp_type, code, payload)
            } else {
                describe_icmpv4(icmp_type, code)
            }
        }
        None => "ICMP message".into(),
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Icmp,
        summary,
    }
}

fn describe_icmpv4(icmp_type: u8, code: u8) -> String {
    match icmp_type {
        0 => "Ping reply (echo reply)".into(),
        3 => "Destination unreachable".into(),
        5 => "Redirect".into(),
        8 => "Ping request (echo request)".into(),
        // RFC 792: code 0 is the hop count running out in transit, code 1 is
        // the reassembly timer expiring on a host that never received every
        // fragment. Both used to read "Time-to-live exceeded", which sends the
        // reader looking for a routing loop when the fault is fragmentation.
        11 => match code {
            1 => "Fragment reassembly time exceeded".into(),
            _ => "Time-to-live exceeded".into(),
        },
        t => format!("ICMP message (type {t})"),
    }
}

/// Whether a Router Advertisement carries a Prefix Information option.
///
/// Walks the option chain rather than scanning for the byte pair `03 04`. The
/// scan this replaces looked anywhere in the message, so any RA whose router
/// lifetime, reachable time or a neighbouring option happened to contain those
/// two bytes was reported as advertising a SLAAC prefix — a claim about how
/// hosts on that link get their addresses. Finding a field by walking the
/// structure rather than searching for its bytes is the rule everywhere else in
/// this crate; the two disagree exactly when it matters.
///
/// RFC 4861 §4.2: the RA header is 16 bytes, then options as
/// `(type, length-in-8-octet-units, data)`. Option type 3 is Prefix
/// Information, and its length is always 4.
fn has_prefix_information(payload: &[u8]) -> bool {
    const RA_HEADER_LEN: usize = 16;
    const PREFIX_INFORMATION: u8 = 3;

    let mut offset = RA_HEADER_LEN;
    while offset + 2 <= payload.len() {
        let opt_type = payload[offset];
        let units = payload[offset + 1] as usize;
        // A zero length is malformed and would loop forever; RFC 4861 says the
        // packet must be discarded, and here it simply ends the walk.
        if units == 0 {
            return false;
        }
        if opt_type == PREFIX_INFORMATION {
            return true;
        }
        offset += units * 8;
    }
    false
}

fn describe_icmpv6(icmp_type: u8, code: u8, payload: &[u8]) -> String {
    match icmp_type {
        1 => "Destination unreachable".into(),
        // RFC 4443 §3.3, the same split as ICMPv4 type 11.
        3 => match code {
            1 => "Fragment reassembly time exceeded".into(),
            _ => "Hop limit exceeded".into(),
        },
        128 => "Ping request (echo request)".into(),
        129 => "Ping reply (echo reply)".into(),
        133 => "Router solicitation".into(),
        134 => {
            if has_prefix_information(payload) {
                "Router Advertisement (SLAAC prefix info)".into()
            } else {
                "Router Advertisement".into()
            }
        }
        135 => "Neighbor solicitation (who has this IPv6?)".into(),
        136 => "Neighbor advertisement".into(),
        137 => "Redirect".into(),
        // Multicast Listener Discovery is IPv6's answer to IGMP: it is how a
        // host says which multicast groups it wants. These arrive behind a
        // hop-by-hop router-alert header, which is why the extension-header
        // walk in `ip` has to run before they can be seen at all.
        130 => "MLD query (who is listening to this group?)".into(),
        131 => "MLD report (I am listening to this group)".into(),
        132 => "MLD done (I have stopped listening)".into(),
        143 => "MLDv2 report (multicast group membership)".into(),
        // Router renumbering and inverse discovery round out the set a router
        // will emit.
        138 => "Router renumbering".into(),
        141 => "Inverse neighbor discovery solicitation".into(),
        142 => "Inverse neighbor discovery advertisement".into(),
        2 => "Packet too big".into(),
        4 => "Parameter problem".into(),
        t => format!("ICMPv6 message (type {t})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_echo_request() {
        let result = dissect_icmp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &[8, 0, 0, 0],
            false,
        );
        assert_eq!(result.protocol, Protocol::Icmp);
        assert_eq!(result.summary, "Ping request (echo request)");
        assert_eq!(result.src_addr, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(result.dst_addr, Some("10.0.0.2".parse().unwrap()));
        assert!(result.src_port.is_none());
    }

    #[test]
    fn icmp_echo_reply() {
        let result = dissect_icmp(None, None, &[0, 0, 0, 0], false);
        assert_eq!(result.summary, "Ping reply (echo reply)");
    }

    #[test]
    fn icmp_ttl_exceeded() {
        let result = dissect_icmp(None, None, &[11, 0], false);
        assert_eq!(result.summary, "Time-to-live exceeded");
    }

    #[test]
    fn icmp_unknown_type() {
        let result = dissect_icmp(None, None, &[42, 0], false);
        assert_eq!(result.summary, "ICMP message (type 42)");
    }

    #[test]
    fn icmpv6_neighbor_solicitation() {
        let result = dissect_icmp(None, None, &[135, 0], true);
        assert_eq!(result.summary, "Neighbor solicitation (who has this IPv6?)");
    }

    #[test]
    fn icmpv6_echo_request() {
        let result = dissect_icmp(None, None, &[128, 0], true);
        assert_eq!(result.summary, "Ping request (echo request)");
    }

    #[test]
    fn icmp_empty_payload() {
        let result = dissect_icmp(None, None, &[], false);
        assert_eq!(result.protocol, Protocol::Icmp);
        assert_eq!(result.summary, "ICMP message");
        assert!(result.src_addr.is_none());
        assert!(result.dst_addr.is_none());
    }

    #[test]
    fn icmp_destination_unreachable() {
        let result = dissect_icmp(None, None, &[3, 0], false);
        assert_eq!(result.summary, "Destination unreachable");
    }

    #[test]
    fn icmp_redirect() {
        let result = dissect_icmp(None, None, &[5, 0], false);
        assert_eq!(result.summary, "Redirect");
    }

    #[test]
    fn icmpv6_parameter_problem() {
        let result = dissect_icmp(None, None, &[4, 0], true);
        assert_eq!(result.summary, "Parameter problem");
    }

    #[test]
    fn icmpv6_packet_too_big() {
        let result = dissect_icmp(None, None, &[2, 0], true);
        assert_eq!(result.summary, "Packet too big");
    }

    #[test]
    fn icmpv6_mld_query() {
        let result = dissect_icmp(None, None, &[130, 0], true);
        assert_eq!(
            result.summary,
            "MLD query (who is listening to this group?)"
        );
    }

    #[test]
    fn icmpv6_mld_report() {
        let result = dissect_icmp(None, None, &[131, 0], true);
        assert_eq!(result.summary, "MLD report (I am listening to this group)");
    }

    #[test]
    fn icmpv6_mld_done() {
        let result = dissect_icmp(None, None, &[132, 0], true);
        assert_eq!(result.summary, "MLD done (I have stopped listening)");
    }

    #[test]
    fn icmpv6_mldv2_report() {
        let result = dissect_icmp(None, None, &[143, 0], true);
        assert_eq!(result.summary, "MLDv2 report (multicast group membership)");
    }

    #[test]
    fn icmpv6_router_renumbering() {
        let result = dissect_icmp(None, None, &[138, 0], true);
        assert_eq!(result.summary, "Router renumbering");
    }

    #[test]
    fn icmpv6_destination_unreachable() {
        let result = dissect_icmp(None, None, &[1, 0], true);
        assert_eq!(result.summary, "Destination unreachable");
    }

    #[test]
    fn icmpv6_hop_limit_exceeded() {
        let result = dissect_icmp(None, None, &[3, 0], true);
        assert_eq!(result.summary, "Hop limit exceeded");
    }

    /// Code 1 of "Time Exceeded" is a different failure from a hop count
    /// running out, and it used to be reported as one.
    ///
    /// A reader told "TTL exceeded" goes looking for a routing loop. The actual
    /// cause is that a host waited for fragments that never all arrived —
    /// usually an MTU or a path problem, and the fix is nowhere near a router's
    /// hop count.
    #[test]
    fn a_reassembly_timeout_is_not_a_hop_count_expiry() {
        assert_eq!(
            dissect_icmp(None, None, &[11, 1], false).summary,
            "Fragment reassembly time exceeded"
        );
        assert_eq!(
            dissect_icmp(None, None, &[11, 0], false).summary,
            "Time-to-live exceeded"
        );
        assert_eq!(
            dissect_icmp(None, None, &[3, 1], true).summary,
            "Fragment reassembly time exceeded"
        );
    }

    /// A Router Advertisement only advertises a SLAAC prefix if it carries the
    /// option, not if the bytes `03 04` appear somewhere in it.
    ///
    /// The old check scanned the whole message. The first case below is the one
    /// it got wrong: a router lifetime of 0x0304 in the header, no options at
    /// all, reported as advertising a prefix — a claim about how every host on
    /// that link gets its address.
    #[test]
    fn a_router_advertisement_needs_the_option_not_the_bytes() {
        // type, code, checksum×2, cur-hop-limit, flags, router lifetime = 0x0304,
        // reachable time ×4, retrans timer ×4. Sixteen bytes, no options.
        let no_options = [134, 0, 0, 0, 64, 0, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            dissect_icmp(None, None, &no_options, true).summary,
            "Router Advertisement",
        );

        // The same header, then a real Prefix Information option: type 3,
        // length 4 (thirty-two bytes).
        let mut with_prefix = no_options.to_vec();
        with_prefix.extend_from_slice(&[3, 4]);
        with_prefix.extend_from_slice(&[0u8; 30]);
        assert_eq!(
            dissect_icmp(None, None, &with_prefix, true).summary,
            "Router Advertisement (SLAAC prefix info)",
        );

        // An option chain that does not include one: Source Link-Layer Address
        // (type 1, length 1) followed by MTU (type 5, length 1).
        let mut other_options = no_options.to_vec();
        other_options.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        other_options.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x03, 0x04]);
        assert_eq!(
            dissect_icmp(None, None, &other_options, true).summary,
            "Router Advertisement",
        );
    }
}
