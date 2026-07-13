//! Linux "cooked" capture dissector — `LINKTYPE_LINUX_SLL` (DLT 113) and
//! `LINKTYPE_LINUX_SLL2` (DLT 276).
//!
//! `tcpdump -i any` (the default interface for netscope's remote capture)
//! can't produce real Ethernet headers because it merges interfaces with
//! different link layers, so libpcap substitutes this pseudo-header. Both
//! variants end in an EtherType, which we hand to the normal L3 dispatch —
//! everything above (IP, TCP, TLS, DNS…) dissects exactly as usual.

use super::{dispatch_l3, DissectedResult};
use crate::models::Protocol;

fn malformed(which: &str) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown(format!("truncated {which}")),
        summary: format!("Malformed Linux cooked capture ({which} header too short)"),
    }
}

/// SLL v1 (16 bytes): packet type, ARPHRD, addr len, addr[8], protocol.
pub fn dissect_sll(data: &[u8]) -> DissectedResult {
    if data.len() < 16 {
        return malformed("SLL");
    }
    let ethertype = u16::from_be_bytes([data[14], data[15]]);
    dispatch_l3(ethertype, &data[16..], 0)
}

/// SLL v2 (20 bytes): protocol first, then reserved, ifindex, ARPHRD,
/// packet type, addr len, addr[8].
pub fn dissect_sll2(data: &[u8]) -> DissectedResult {
    if data.len() < 20 {
        return malformed("SLL2");
    }
    let ethertype = u16::from_be_bytes([data[0], data[1]]);
    dispatch_l3(ethertype, &data[20..], 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::build_dns_query;

    /// A raw IPv4/UDP/DNS payload (no Ethernet header).
    fn ipv4_udp_dns() -> Vec<u8> {
        let dns = build_dns_query("example.com", 7);
        let udp_len = 8 + dns.len();
        let total = 20 + udp_len;
        let mut v = Vec::new();
        v.push(0x45); // IPv4, IHL 5
        v.push(0);
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]); // id, flags
        v.push(64); // TTL
        v.push(17); // UDP
        v.extend_from_slice(&[0, 0]); // checksum
        v.extend_from_slice(&[10, 0, 0, 1]);
        v.extend_from_slice(&[8, 8, 8, 8]);
        v.extend_from_slice(&12345u16.to_be_bytes());
        v.extend_from_slice(&53u16.to_be_bytes());
        v.extend_from_slice(&(udp_len as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&dns);
        v
    }

    #[test]
    fn sll_v1_reaches_dns() {
        let mut frame = vec![0u8; 14]; // pkttype, arphrd, addrlen, addr
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        frame.extend_from_slice(&ipv4_udp_dns());
        let r = dissect_sll(&frame);
        assert_eq!(r.protocol, Protocol::Dns, "{}", r.summary);
        assert_eq!(r.dst_port, Some(53));
    }

    #[test]
    fn sll_v2_reaches_dns() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol first
        frame.extend_from_slice(&[0u8; 18]); // reserved…addr
        frame.extend_from_slice(&ipv4_udp_dns());
        let r = dissect_sll2(&frame);
        assert_eq!(r.protocol, Protocol::Dns, "{}", r.summary);
    }

    #[test]
    fn truncated_headers() {
        assert!(matches!(dissect_sll(&[0; 10]).protocol, Protocol::Unknown(_)));
        assert!(matches!(dissect_sll2(&[0; 19]).protocol, Protocol::Unknown(_)));
    }
}
