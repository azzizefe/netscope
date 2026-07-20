// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// The base header plus the service path header (RFC 8300 §2.2).
const HEADER: usize = 8;
/// Version 0 is the only one defined, in the top two bits.
const VERSION_MASK: u8 = 0xC0;

/// What the NSH is carrying (RFC 8300 §2.5).
fn next_protocol(p: u8) -> Option<&'static str> {
    Some(match p {
        0x01 => "IPv4",
        0x02 => "IPv6",
        0x03 => "Ethernet",
        0x04 => "NSH",
        0x05 => "MPLS",
        0xFE => "experiment 1",
        0xFF => "experiment 2",
        _ => return None,
    })
}

/// Metadata type: a fixed 16-byte context, or variable TLVs (RFC 8300 §2.4).
fn md_type(t: u8) -> &'static str {
    match t {
        0x1 => "fixed metadata",
        0x2 => "variable metadata",
        _ => "unknown metadata",
    }
}

/// Dissect a Network Service Header — the thing that steers a packet through a
/// chain of firewalls, load balancers and inspection boxes (RFC 8300).
///
/// Without NSH, sending traffic through a series of appliances means physically
/// cabling them in order or fighting with policy routing. NSH puts the itinerary
/// in the packet: a service path identifier names the chain, and a service index
/// counts down as each appliance handles it. Reaching index zero means the
/// packet has been through everything it was supposed to.
pub fn dissect_nsh(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Nsh,
        summary,
    };
    if payload.len() < HEADER {
        return result(format!("NSH ({})", super::bytes(payload.len() as u64)));
    }
    if payload[0] & VERSION_MASK != 0 {
        return result(format!("NSH (unexpected version {})", payload[0] >> 6));
    }
    // The O bit marks a packet carrying operations and maintenance data rather
    // than a customer's traffic.
    let oam = payload[0] & 0x20 != 0;
    // The metadata type is the low four bits of the second byte.
    let metadata = md_type(payload[1] & 0x0F);
    let carried = payload[3];
    // Service path identifier is 24 bits, then the 8-bit index.
    let path = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
    let index = payload[7];

    let inner = match next_protocol(carried) {
        Some(name) => name.to_string(),
        None => format!("protocol 0x{carried:02x}"),
    };
    let summary = if oam {
        format!("NSH OAM — path {path}, index {index}, {metadata}")
    } else {
        format!("NSH path {path}, index {index} — carrying {inner}")
    };
    result(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an NSH header.
    fn nsh(oam: bool, md: u8, next: u8, path: u32, index: u8) -> Vec<u8> {
        let mut p = vec![
            if oam { 0x20 } else { 0x00 },
            (0x06 << 4) | (md & 0x0F), // length in 4-byte words, metadata type
            0x00,
            next,
        ];
        p.extend_from_slice(&path.to_be_bytes()[1..]); // 24-bit path id
        p.push(index);
        p
    }

    #[test]
    fn service_path_and_index_are_reported() {
        let r = dissect_nsh(&nsh(false, 1, 0x03, 42, 255));
        assert_eq!(r.protocol, Protocol::Nsh);
        assert_eq!(r.summary, "NSH path 42, index 255 — carrying Ethernet");
    }

    /// The index counting down is how you see where in the chain a packet is.
    #[test]
    fn index_counts_down_through_the_chain() {
        let entering = dissect_nsh(&nsh(false, 1, 0x01, 7, 255));
        let midway = dissect_nsh(&nsh(false, 1, 0x01, 7, 253));
        let done = dissect_nsh(&nsh(false, 1, 0x01, 7, 0));
        assert!(entering.summary.contains("index 255"));
        assert!(midway.summary.contains("index 253"));
        assert!(done.summary.contains("index 0"));
    }

    /// The path identifier is 24 bits; reading it as 32 would fold the next
    /// protocol byte into it and report a nonsense path.
    #[test]
    fn path_identifier_is_twenty_four_bits() {
        let r = dissect_nsh(&nsh(false, 1, 0xFF, 0x00FF_FFFF, 1));
        assert!(r.summary.contains("path 16777215"));
    }

    /// An operations packet is not customer traffic and should read as such.
    #[test]
    fn oam_packets_are_distinguished() {
        let r = dissect_nsh(&nsh(true, 2, 0x01, 9, 250));
        assert_eq!(r.summary, "NSH OAM — path 9, index 250, variable metadata");
    }

    #[test]
    fn unknown_carried_protocol_reports_its_byte() {
        let r = dissect_nsh(&nsh(false, 1, 0x7E, 1, 1));
        assert!(r.summary.ends_with("carrying protocol 0x7e"));
    }

    #[test]
    fn foreign_version_is_not_decoded() {
        let mut p = nsh(false, 1, 0x03, 1, 1);
        p[0] = 0x40;
        assert_eq!(dissect_nsh(&p).summary, "NSH (unexpected version 1)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_nsh(&[0x00, 0x61, 0x00]);
        assert_eq!(r.summary, "NSH (3 bytes)");
    }
}
