//! Passive hostname resolution.
//!
//! Watches DNS responses as they fly by and remembers which IP belongs to
//! which domain. This is what lets netscope show `google.com → 142.250.74.46`
//! instead of two bare IPs — no extra lookups, no network traffic of its own.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::models::{Packet, Protocol};

/// Keep memory bounded on long captures; ~50k names is far beyond
/// what a normal session sees.
const MAX_ENTRIES: usize = 50_000;

#[derive(Debug, Default)]
pub struct NameCache {
    map: HashMap<IpAddr, String>,
}

impl NameCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Learn IP → hostname mappings from a DNS response packet.
    /// Safe to call with any packet; non-DNS packets are ignored.
    pub fn observe(&mut self, pkt: &Packet) {
        if pkt.protocol != Protocol::Dns {
            return;
        }
        let Some(payload) = udp_payload(&pkt.data) else {
            return;
        };
        let Ok(dns) = dns_parser::Packet::parse(payload) else {
            return;
        };
        if dns.header.query {
            return;
        }
        let Some(domain) = dns.questions.first().map(|q| q.qname.to_string()) else {
            return;
        };
        if self.map.len() >= MAX_ENTRIES {
            return;
        }
        for answer in &dns.answers {
            match answer.data {
                dns_parser::RData::A(ip) => {
                    self.map.insert(IpAddr::V4(ip.0), domain.clone());
                }
                dns_parser::RData::AAAA(ip) => {
                    self.map.insert(IpAddr::V6(ip.0), domain.clone());
                }
                _ => {}
            }
        }
    }

    /// The hostname learned for this IP, if any.
    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        self.map.get(&ip).map(|s| s.as_str())
    }

    /// Display form for an address: the hostname when known, the IP otherwise.
    pub fn display(&self, ip: IpAddr) -> String {
        match self.name_for(ip) {
            Some(name) => name.to_string(),
            None => ip.to_string(),
        }
    }

    /// Display form for an endpoint: `github.com:443`, `[2001:db8::1]:443`,
    /// or a bare address when there is no port.
    pub fn display_endpoint(&self, ip: IpAddr, port: Option<u16>) -> String {
        match (self.name_for(ip), port) {
            (Some(name), Some(p)) => format!("{name}:{p}"),
            (Some(name), None) => name.to_string(),
            (None, port) => crate::models::format_endpoint(ip, port),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Extract the UDP payload from a raw Ethernet frame.
fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let sliced = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    match sliced.transport {
        Some(etherparse::TransportSlice::Udp(udp)) => Some(udp.payload()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{build_dns_query, build_dns_response, build_udp_packet};
    use chrono::Utc;

    fn dns_packet(frame: Vec<u8>) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.2".parse().unwrap()),
            dst_addr: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(53),
            dst_port: Some(54321),
            protocol: Protocol::Dns,
            length: frame.len(),
            summary: String::new(),
            data: frame,
        }
    }

    #[test]
    fn learns_from_dns_response() {
        let payload = build_dns_response("github.com", 0x1234, [140, 82, 121, 4]);
        let frame = build_udp_packet([10, 0, 0, 2], [10, 0, 0, 1], 53, 54321, &payload);
        let mut cache = NameCache::new();
        cache.observe(&dns_packet(frame));

        let ip: IpAddr = "140.82.121.4".parse().unwrap();
        assert_eq!(cache.name_for(ip), Some("github.com"));
        assert_eq!(cache.display(ip), "github.com");
        assert_eq!(cache.display_endpoint(ip, Some(443)), "github.com:443");
    }

    #[test]
    fn ignores_dns_queries() {
        let payload = build_dns_query("github.com", 0x1234);
        let frame = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &payload);
        let mut cache = NameCache::new();
        cache.observe(&dns_packet(frame));
        assert!(cache.is_empty());
    }

    #[test]
    fn ignores_non_dns_packets() {
        let mut pkt = dns_packet(vec![1, 2, 3]);
        pkt.protocol = Protocol::Tcp;
        let mut cache = NameCache::new();
        cache.observe(&pkt);
        assert!(cache.is_empty());
    }

    #[test]
    fn unknown_ip_falls_back_to_address() {
        let cache = NameCache::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(cache.display(ip), "8.8.8.8");
        assert_eq!(cache.display_endpoint(ip, Some(53)), "8.8.8.8:53");
    }

    #[test]
    fn ipv6_unknown_keeps_brackets() {
        let cache = NameCache::new();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(cache.display_endpoint(ip, Some(443)), "[2001:db8::1]:443");
    }

    #[test]
    fn malformed_frame_is_ignored() {
        let mut cache = NameCache::new();
        cache.observe(&dns_packet(vec![0xff; 20]));
        assert!(cache.is_empty());
    }
}
