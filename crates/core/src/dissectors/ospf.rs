// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::{IpAddr, Ipv4Addr};

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OSPF packet (IP protocol 89).
///
/// OSPF is the routing protocol most enterprises use inside their own network —
/// routers flood each other with link-state information and independently
/// compute shortest paths. Every packet shares a 24-byte header: version(1),
/// type(1), length(2), router id(4), area id(4), checksum(2), auth type(2),
/// auth(8). The type names the exchange — Hello discovers neighbours, the
/// Database Description / LSR / LSU / LSAck quartet synchronises the link-state
/// database. We surface the type, router id and area.
pub fn dissect_ospf(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ospf,
        summary: String::new(),
    };

    if payload.len() < 24 {
        return DissectedResult {
            summary: "OSPF (partial)".into(),
            ..base
        };
    }

    let version = payload[0];
    let msg_type = payload[1];
    let router_id = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
    let area_id = Ipv4Addr::new(payload[8], payload[9], payload[10], payload[11]);

    DissectedResult {
        summary: format!(
            "OSPFv{version} {} — router {router_id}, area {area_id}",
            type_name(msg_type)
        ),
        ..base
    }
}

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "Hello",
        2 => "Database Description",
        3 => "Link State Request",
        4 => "Link State Update",
        5 => "Link State Acknowledgment",
        _ => "packet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, msg_type: u8, router: [u8; 4], area: [u8; 4]) -> Vec<u8> {
        let mut p = vec![version, msg_type, 0x00, 0x2c];
        p.extend_from_slice(&router);
        p.extend_from_slice(&area);
        p.extend_from_slice(&[0u8; 12]); // checksum, auth type, auth
        p
    }

    #[test]
    fn hello_packet() {
        let p = header(2, 1, [10, 0, 0, 1], [0, 0, 0, 0]);
        let r = dissect_ospf(None, None, &p);
        assert_eq!(r.protocol, Protocol::Ospf);
        assert_eq!(r.summary, "OSPFv2 Hello — router 10.0.0.1, area 0.0.0.0");
    }

    #[test]
    fn lsu_packet() {
        let p = header(2, 4, [192, 168, 1, 1], [0, 0, 0, 1]);
        let r = dissect_ospf(None, None, &p);
        assert_eq!(
            r.summary,
            "OSPFv2 Link State Update — router 192.168.1.1, area 0.0.0.1"
        );
    }

    #[test]
    fn partial_is_safe() {
        let r = dissect_ospf(None, None, &[2, 1, 0]);
        assert!(r.summary.contains("partial"));
    }
}
