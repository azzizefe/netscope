// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PKTAP — macOS packet tap metadata (`DLT_PKTAP`).
//!
//! Capturing with `tcpdump -i pktap` on macOS prefixes every packet with a
//! header the kernel fills in, and it carries something no other capture format
//! has: the process that produced the packet. That answers a question a
//! developer asks constantly and normally cannot — not "what went to this
//! address" but "which application on my machine sent it".
//!
//! Only the fields with unambiguous offsets are read. The header ends with
//! several more, including UUIDs, whose positions depend on struct alignment
//! that varies by build; the declared header length is used to find the packet
//! rather than assuming a fixed size.

use super::{dissect_linktype, DissectedResult};
use crate::models::Protocol;

/// The header's declared length is its own first field.
const OFFSET_LENGTH: usize = 0;
/// The link type of the packet that follows.
const OFFSET_DLT: usize = 8;
/// A fixed-size interface name, NUL-padded.
const OFFSET_IFNAME: usize = 12;
const IFNAME_LEN: usize = 24;
/// The process id and name of whatever produced the packet.
const OFFSET_PID: usize = 52;
const OFFSET_COMM: usize = 56;
const COMM_LEN: usize = 17;

/// Enough of the header to reach the process name.
const MIN_HEADER: usize = OFFSET_COMM + COMM_LEN;
/// A header longer than this is not something the kernel writes; the cap stops
/// a malformed length from being trusted.
const MAX_HEADER: usize = 256;

/// Read a NUL-padded fixed-width string.
fn fixed_string(data: &[u8], at: usize, len: usize) -> Option<String> {
    let field = data.get(at..at + len)?;
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Dissect a packet carrying a macOS packet-tap header.
pub fn dissect_pktap(data: &[u8]) -> DissectedResult {
    let malformed = |reason: &str| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown(reason.to_string()),
        summary: format!("Malformed packet ({reason})"),
    };

    if data.len() < MIN_HEADER {
        return malformed("truncated PKTAP header");
    }
    let Some(header_len) = read_u32(data, OFFSET_LENGTH).map(|l| l as usize) else {
        return malformed("truncated PKTAP header");
    };
    if !(MIN_HEADER..=MAX_HEADER).contains(&header_len) || header_len > data.len() {
        return malformed("implausible PKTAP header length");
    }

    let dlt = read_u32(data, OFFSET_DLT).unwrap_or(1) as i32;
    let interface = fixed_string(data, OFFSET_IFNAME, IFNAME_LEN);
    let pid = read_u32(data, OFFSET_PID).map(|p| p as i32);
    let process = fixed_string(data, OFFSET_COMM, COMM_LEN);

    // A nested packet tap is not a thing the kernel produces, and following one
    // would recurse; treat it as malformed rather than looping.
    if dlt == super::DLT_PKTAP {
        return malformed("nested PKTAP header");
    }

    let mut inner = dissect_linktype(&data[header_len..], dlt);

    // The process is the fact this format exists to carry, so it leads.
    let mut prefix = Vec::new();
    if let Some(iface) = interface {
        prefix.push(iface);
    }
    match (process, pid) {
        (Some(name), Some(pid)) if pid > 0 => prefix.push(format!("{name}[{pid}]")),
        (Some(name), _) => prefix.push(name),
        _ => {}
    }
    if !prefix.is_empty() {
        inner.summary = format!("{} · {}", prefix.join(" "), inner.summary);
    }
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PKTAP header in front of `packet`.
    fn pktap(interface: &str, process: &str, pid: u32, dlt: i32, packet: &[u8]) -> Vec<u8> {
        let header_len = 128usize;
        let mut p = vec![0u8; header_len];
        p[OFFSET_LENGTH..OFFSET_LENGTH + 4].copy_from_slice(&(header_len as u32).to_le_bytes());
        p[OFFSET_DLT..OFFSET_DLT + 4].copy_from_slice(&(dlt as u32).to_le_bytes());
        p[OFFSET_IFNAME..OFFSET_IFNAME + interface.len()].copy_from_slice(interface.as_bytes());
        p[OFFSET_PID..OFFSET_PID + 4].copy_from_slice(&pid.to_le_bytes());
        p[OFFSET_COMM..OFFSET_COMM + process.len()].copy_from_slice(process.as_bytes());
        p.extend_from_slice(packet);
        p
    }

    /// A raw-IP packet carrying a DNS query, so the result proves the inner
    /// link type was honoured too.
    fn ip_dns() -> Vec<u8> {
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

    /// The whole reason this format exists: naming the process behind a packet.
    #[test]
    fn the_process_and_interface_lead_the_summary() {
        let p = pktap("en0", "firefox", 4242, 101, &ip_dns());
        let r = dissect_pktap(&p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "en0 firefox[4242] · DNS Query — example.com");
    }

    /// The inner link type is whatever the interface actually is, so it has to
    /// be honoured rather than assumed to be Ethernet.
    #[test]
    fn the_inner_link_type_is_honoured() {
        // DLT_NULL: a loopback frame, which needs its address-family header
        // stripped before the IP packet starts.
        let mut loopback = 2u32.to_le_bytes().to_vec();
        loopback.extend_from_slice(&ip_dns());
        let r = dissect_pktap(&pktap("lo0", "curl", 99, 0, &loopback));
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "lo0 curl[99] · DNS Query — example.com");
    }

    /// Some packets have no owning process — anything the kernel itself emits.
    #[test]
    fn a_packet_with_no_process_still_decodes() {
        let p = pktap("en0", "", 0, 101, &ip_dns());
        let r = dissect_pktap(&p);
        assert_eq!(r.summary, "en0 · DNS Query — example.com");
    }

    /// A nested tap would recurse, so it is refused rather than followed.
    #[test]
    fn a_nested_tap_is_refused() {
        let p = pktap("en0", "x", 1, super::super::DLT_PKTAP, &ip_dns());
        assert!(dissect_pktap(&p).summary.contains("nested PKTAP"));
    }

    /// The declared length is what locates the packet, so an implausible one
    /// has to be rejected rather than used as an offset.
    #[test]
    fn an_implausible_header_length_is_rejected() {
        let mut p = pktap("en0", "x", 1, 101, &ip_dns());
        p[0..4].copy_from_slice(&9_999u32.to_le_bytes());
        assert!(dissect_pktap(&p)
            .summary
            .contains("implausible PKTAP header length"));

        let mut p = pktap("en0", "x", 1, 101, &ip_dns());
        p[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(dissect_pktap(&p)
            .summary
            .contains("implausible PKTAP header length"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(dissect_pktap(&[0u8; 8]).summary.contains("truncated"));
        assert!(dissect_pktap(&[]).summary.contains("truncated"));
    }
}
