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
            if is_v6 {
                describe_icmpv6(icmp_type)
            } else {
                describe_icmpv4(icmp_type)
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

fn describe_icmpv4(icmp_type: u8) -> String {
    match icmp_type {
        0 => "Ping reply (echo reply)".into(),
        3 => "Destination unreachable".into(),
        5 => "Redirect".into(),
        8 => "Ping request (echo request)".into(),
        11 => "Time-to-live exceeded".into(),
        t => format!("ICMP message (type {t})"),
    }
}

fn describe_icmpv6(icmp_type: u8) -> String {
    match icmp_type {
        1 => "Destination unreachable".into(),
        3 => "Hop limit exceeded".into(),
        128 => "Ping request (echo request)".into(),
        129 => "Ping reply (echo reply)".into(),
        133 => "Router solicitation".into(),
        134 => "Router advertisement".into(),
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
}
