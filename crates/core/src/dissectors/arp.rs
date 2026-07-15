// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ethernet::mac_to_string, DissectedResult};

pub struct ArpInfo {
    pub operation: ArpOperation,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

pub enum ArpOperation {
    Request,
    Reply,
    Other(u16),
}

pub fn dissect_arp(data: &[u8]) -> DissectedResult {
    let arp = match parse_arp(data) {
        Some(a) => a,
        None => {
            return DissectedResult {
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Arp,
                summary: "Malformed ARP packet".into(),
            };
        }
    };

    let sender_ip = IpAddr::V4(std::net::Ipv4Addr::from(arp.sender_ip));
    let target_ip = IpAddr::V4(std::net::Ipv4Addr::from(arp.target_ip));

    let summary = match arp.operation {
        ArpOperation::Request => {
            format!(
                "ARP Request — Who has {}? Tell {} ({})",
                target_ip,
                sender_ip,
                mac_to_string(&arp.sender_mac)
            )
        }
        ArpOperation::Reply => {
            format!(
                "ARP Reply — {} is at {}",
                sender_ip,
                mac_to_string(&arp.sender_mac)
            )
        }
        ArpOperation::Other(_) => "ARP — unknown operation".into(),
    };

    DissectedResult {
        src_addr: Some(sender_ip),
        dst_addr: Some(target_ip),
        src_port: None,
        dst_port: None,
        protocol: Protocol::Arp,
        summary,
    }
}

fn parse_arp(data: &[u8]) -> Option<ArpInfo> {
    if data.len() < 28 {
        return None;
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&data[14..18]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&data[18..24]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&data[24..28]);

    let operation = match op {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        _ => ArpOperation::Other(op),
    };

    Some(ArpInfo {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::build_arp_packet;

    #[test]
    fn arp_request() {
        let data = build_arp_packet(
            1, // request
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 168, 1, 1],
            &[0; 6],
            &[192, 168, 1, 2],
        );
        let result = dissect_arp(&data[14..]); // skip ethernet
        assert_eq!(result.protocol, Protocol::Arp);
        assert_eq!(
            result.summary,
            "ARP Request — Who has 192.168.1.2? Tell 192.168.1.1 (aa:bb:cc:dd:ee:ff)"
        );
    }

    #[test]
    fn arp_reply() {
        let data = build_arp_packet(
            2, // reply
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 168, 1, 1],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            &[192, 168, 1, 2],
        );
        let result = dissect_arp(&data[14..]); // skip ethernet
        assert_eq!(result.protocol, Protocol::Arp);
        assert_eq!(
            result.summary,
            "ARP Reply — 192.168.1.1 is at aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn arp_malformed() {
        let result = dissect_arp(&[0; 10]);
        assert_eq!(result.summary, "Malformed ARP packet");
    }

    #[test]
    fn arp_unknown_operation() {
        let data = build_arp_packet(
            42,
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 168, 1, 1],
            &[0; 6],
            &[192, 168, 1, 2],
        );
        let result = dissect_arp(&data[14..]);
        assert_eq!(result.protocol, Protocol::Arp);
        assert_eq!(result.summary, "ARP — unknown operation");
    }

    #[test]
    fn arp_truncated_data() {
        let result = dissect_arp(&[]);
        assert_eq!(result.summary, "Malformed ARP packet");
        let result = dissect_arp(&[0; 27]);
        assert_eq!(result.summary, "Malformed ARP packet");
    }
}
