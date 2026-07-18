// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name the payload an GRE tunnel is carrying, from its inner protocol type
/// (an EtherType value, RFC 2784 / RFC 2637).
fn inner_name(proto_type: u16) -> &'static str {
    match proto_type {
        0x0800 => "IPv4",
        0x86DD => "IPv6",
        0x8847 => "MPLS",
        0x6558 => "Ethernet (NVGRE/bridging)",
        0x880B => "PPP (PPTP)",
        _ => "payload",
    }
}

/// Dissect a GRE packet (IP protocol 47). The 4-byte base header carries flags
/// and the protocol type of the tunnelled payload (RFC 2784).
pub fn dissect_gre(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    if payload.len() >= 4 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
        // ERSPAN rides GRE with its own protocol types; hand it the payload
        // past the optional checksum/key/sequence fields.
        if proto_type == 0x88BE || proto_type == 0x22EB {
            let mut hdr = 4;
            if flags & 0x8000 != 0 {
                hdr += 4; // checksum present
            }
            if flags & 0x2000 != 0 {
                hdr += 4; // key present
            }
            if flags & 0x1000 != 0 {
                hdr += 4; // sequence number present
            }
            if payload.len() > hdr {
                return super::erspan::dissect_erspan(src_ip, dst_ip, &payload[hdr..]);
            }
        }
    }
    let summary = if payload.len() >= 4 {
        let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
        format!("GRE — tunnelling {}", inner_name(proto_type))
    } else {
        "GRE (truncated header)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Gre,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_tunnel() {
        // Flags 0x0000, protocol type 0x0800 (IPv4).
        let r = dissect_gre(None, None, &[0x00, 0x00, 0x08, 0x00]);
        assert_eq!(r.protocol, Protocol::Gre);
        assert_eq!(r.summary, "GRE — tunnelling IPv4");
    }

    #[test]
    fn pptp_ppp() {
        let r = dissect_gre(None, None, &[0x30, 0x01, 0x88, 0x0B]);
        assert!(r.summary.contains("PPP"));
    }
}
