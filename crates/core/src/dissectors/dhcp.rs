// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::{IpAddr, Ipv4Addr};

use crate::models::Protocol;

use super::DissectedResult;

/// The BOOTP fixed header is 236 bytes; DHCP appends a 4-byte magic cookie
/// (0x63825363) followed by a TLV option list.
const BOOTP_FIXED_LEN: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Dissect a DHCP / BOOTP message (UDP 67/68). Reports the DHCP message type
/// (Discover / Offer / Request / ACK / …) and, for Offer/ACK, the offered
/// address (`yiaddr`).
pub fn dissect_dhcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dhcp,
        summary,
    };

    if payload.len() < BOOTP_FIXED_LEN {
        return result("DHCP (truncated)".into());
    }

    // yiaddr — "your" (client) address the server is assigning — is at offset 16.
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    // Options begin after the magic cookie, if present.
    let msg_type = if payload.len() >= BOOTP_FIXED_LEN + 4
        && payload[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4] == MAGIC_COOKIE
    {
        find_option_53(&payload[BOOTP_FIXED_LEN + 4..])
    } else {
        None
    };

    let summary = match msg_type {
        Some(t) => {
            let name = dhcp_type_name(t);
            // Offer (2) and ACK (5) carry the assigned address.
            if (t == 2 || t == 5) && !yiaddr.is_unspecified() {
                format!("DHCP {name} — {yiaddr}")
            } else {
                format!("DHCP {name}")
            }
        }
        None => match payload[0] {
            1 => "DHCP/BOOTP Request".into(),
            2 => "DHCP/BOOTP Reply".into(),
            _ => "DHCP/BOOTP message".into(),
        },
    };

    result(summary)
}

/// Scan the DHCP option TLV list for option 53 (message type). Options are
/// `tag, len, value…`; tag 0 is padding and tag 255 (End) terminates the list.
fn find_option_53(mut opts: &[u8]) -> Option<u8> {
    while let Some((&tag, rest)) = opts.split_first() {
        match tag {
            0 => opts = rest, // Pad
            255 => break,     // End
            _ => {
                let len = *rest.first()? as usize;
                let value = rest.get(1..1 + len)?;
                if tag == 53 {
                    return value.first().copied();
                }
                opts = &rest[1 + len..];
            }
        }
    }
    None
}

fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP packet: BOOTP header + cookie + option 53.
    fn dhcp_packet(op: u8, yiaddr: [u8; 4], msg_type: Option<u8>) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_FIXED_LEN];
        p[0] = op;
        p[16..20].copy_from_slice(&yiaddr);
        if let Some(t) = msg_type {
            p.extend_from_slice(&MAGIC_COOKIE);
            p.extend_from_slice(&[53, 1, t]); // option 53, len 1, value
            p.push(255); // End
        }
        p
    }

    #[test]
    fn discover_is_labeled() {
        let pkt = dhcp_packet(1, [0, 0, 0, 0], Some(1));
        let r = dissect_dhcp(None, None, 68, 67, &pkt);
        assert_eq!(r.protocol, Protocol::Dhcp);
        assert_eq!(r.summary, "DHCP Discover");
    }

    #[test]
    fn offer_includes_assigned_address() {
        let pkt = dhcp_packet(2, [192, 168, 1, 50], Some(2));
        let r = dissect_dhcp(None, None, 67, 68, &pkt);
        assert_eq!(r.summary, "DHCP Offer — 192.168.1.50");
    }

    #[test]
    fn ack_includes_assigned_address() {
        let pkt = dhcp_packet(2, [10, 0, 0, 7], Some(5));
        let r = dissect_dhcp(None, None, 67, 68, &pkt);
        assert_eq!(r.summary, "DHCP ACK — 10.0.0.7");
    }

    #[test]
    fn bootp_without_options_falls_back_to_op() {
        let pkt = dhcp_packet(1, [0, 0, 0, 0], None);
        let r = dissect_dhcp(None, None, 68, 67, &pkt);
        assert_eq!(r.summary, "DHCP/BOOTP Request");
    }

    #[test]
    fn truncated_is_handled() {
        let r = dissect_dhcp(None, None, 68, 67, &[0u8; 10]);
        assert_eq!(r.protocol, Protocol::Dhcp);
        assert!(r.summary.contains("truncated"));
    }
}
