// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The protocol type PPTP uses for its enhanced GRE.
const PPTP_PROTOCOL_TYPE: u16 = 0x880B;
/// Set when an acknowledgement number follows the payload length and call id.
const PPTP_FLAG_ACK: u16 = 0x0080;

/// How long a PPTP enhanced-GRE header is.
///
/// It always carries a key — which here holds the payload length and call id —
/// and adds a sequence number and an acknowledgement number independently, so
/// the payload starts at one of three possible offsets.
fn pptp_header_len(flags: u16) -> usize {
    let mut len = 4 + 4; // base header, then the key
    if flags & 0x1000 != 0 {
        len += 4; // sequence number
    }
    if flags & PPTP_FLAG_ACK != 0 {
        len += 4; // acknowledgement number
    }
    len
}

/// EtherType values a GRE tunnel can carry that we unwrap.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// How long the GRE header is, given its flags.
///
/// The base header is four bytes, and three optional fields may follow. Each
/// is signalled by its own flag bit, so the payload does not start at a fixed
/// offset — assuming it does lands in the middle of the key or sequence number.
fn gre_header_len(flags: u16) -> usize {
    let mut len = 4;
    if flags & 0x8000 != 0 {
        len += 4; // checksum and reserved
    }
    if flags & 0x2000 != 0 {
        len += 4; // key
    }
    if flags & 0x1000 != 0 {
        len += 4; // sequence number
    }
    len
}

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
            let hdr = gre_header_len(flags);
            if payload.len() > hdr {
                return super::erspan::dissect_erspan(src_ip, dst_ip, &payload[hdr..]);
            }
        }
    }
    // A GRE tunnel carrying IP is not interesting in itself — what it is
    // carrying is. Site-to-site VPNs and cloud transit links are mostly this,
    // and without unwrapping, every packet inside one is invisible.
    if payload.len() >= 4 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
        let version = flags & 0x0007;
        if version == 0 {
            let header = gre_header_len(flags);
            if let Some(inner) = payload.get(header..) {
                if !inner.is_empty() && matches!(proto_type, ETHERTYPE_IPV4 | ETHERTYPE_IPV6) {
                    let mut r = super::dispatch_l3(proto_type, inner, 0);
                    r.summary = format!("GRE · {}", r.summary);
                    return r;
                }
            }
        }
        // Version 1 is PPTP's enhanced GRE. Its payload is a PPP frame rather
        // than a plain EtherType, and its optional fields differ: there is
        // always a key, an acknowledgement number may follow the sequence
        // number, and the checksum and routing bits are not used.
        if version == 1 && proto_type == PPTP_PROTOCOL_TYPE {
            if let Some(inner) = payload.get(pptp_header_len(flags)..) {
                if !inner.is_empty() {
                    let mut r = super::ppp::dissect_ppp(inner);
                    r.summary = format!("PPTP · {}", r.summary);
                    return r;
                }
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

    /// PPTP's header is laid out differently from ordinary GRE: the key is
    /// always present and an acknowledgement number may follow the sequence
    /// number, so the payload starts at one of three offsets.
    #[test]
    fn pptp_payload_offset_follows_its_own_flags() {
        // Key only: base header plus four bytes.
        assert_eq!(pptp_header_len(0x2001), 8);
        // Key and sequence number.
        assert_eq!(pptp_header_len(0x3001), 12);
        // Key, sequence and acknowledgement numbers.
        assert_eq!(pptp_header_len(0x3081), 16);
    }

    /// A PPTP tunnel carries PPP, and that PPP frame carries the user's
    /// traffic — reporting the tunnel alone hides all of it.
    #[test]
    fn a_pptp_tunnel_reveals_the_ppp_inside() {
        let flags: u16 = 0x3001; // version 1, key and sequence present
        let mut p = flags.to_be_bytes().to_vec();
        p.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPTP protocol type
        p.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // payload length, call id
        p.extend_from_slice(&[0u8; 4]); // sequence number
        p.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]); // PPP carrying IP
        p.extend_from_slice(&[0x45, 0x00]);

        let r = dissect_gre(None, None, &p);
        assert!(r.summary.starts_with("PPTP · "), "got {}", r.summary);
    }

    #[test]
    fn pptp_ppp() {
        let r = dissect_gre(None, None, &[0x30, 0x01, 0x88, 0x0B]);
        assert!(r.summary.contains("PPP"));
    }
}
