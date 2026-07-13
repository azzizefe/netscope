use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::models::{Packet, Protocol};

#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub total_packets: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub per_protocol: HashMap<Protocol, ProtocolStats>,
    pub current_bandwidth: f64,
    pub average_bandwidth: f64,
    pub top_talkers_sent: Vec<(IpAddr, u64)>,
    pub top_talkers_received: Vec<(IpAddr, u64)>,
    pub top_domains: Vec<(String, u64)>,
    pub len_distribution: [u64; 5],
    pub protocol_hierarchy: Vec<(String, u64, u64)>,
}

#[derive(Debug)]
pub struct StatsEngine {
    total_packets: u64,
    total_bytes: u64,
    per_protocol: HashMap<Protocol, ProtocolStats>,
    bytes_this_second: u64,
    last_second_check: Instant,
    bandwidth_samples: Vec<f64>,
    sent_by_ip: HashMap<IpAddr, u64>,
    received_by_ip: HashMap<IpAddr, u64>,
    domain_counts: HashMap<String, u64>,
    len_distribution: [u64; 5],
    eth_packets: u64,
    eth_bytes: u64,
    ip4_packets: u64,
    ip4_bytes: u64,
    ip6_packets: u64,
    ip6_bytes: u64,
    arp_packets: u64,
    arp_bytes: u64,
    tcp_packets: u64,
    tcp_bytes: u64,
    udp_packets: u64,
    udp_bytes: u64,
    icmp_packets: u64,
    icmp_bytes: u64,
}

impl Default for StatsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsEngine {
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            per_protocol: HashMap::new(),
            bytes_this_second: 0,
            last_second_check: Instant::now(),
            bandwidth_samples: Vec::with_capacity(60),
            sent_by_ip: HashMap::new(),
            received_by_ip: HashMap::new(),
            domain_counts: HashMap::new(),
            len_distribution: [0; 5],
            eth_packets: 0,
            eth_bytes: 0,
            ip4_packets: 0,
            ip4_bytes: 0,
            ip6_packets: 0,
            ip6_bytes: 0,
            arp_packets: 0,
            arp_bytes: 0,
            tcp_packets: 0,
            tcp_bytes: 0,
            udp_packets: 0,
            udp_bytes: 0,
            icmp_packets: 0,
            icmp_bytes: 0,
        }
    }

    pub fn record_packet(&mut self, packet: &Packet) {
        self.total_packets += 1;
        let bytes = packet.length as u64;
        self.total_bytes += bytes;
        self.bytes_this_second += bytes;

        // Buckets: 0-79, 80-639, 640-1279, 1280-1500, >1500
        if packet.length <= 79 {
            self.len_distribution[0] += 1;
        } else if packet.length <= 639 {
            self.len_distribution[1] += 1;
        } else if packet.length <= 1279 {
            self.len_distribution[2] += 1;
        } else if packet.length <= 1500 {
            self.len_distribution[3] += 1;
        } else {
            self.len_distribution[4] += 1;
        }

        self.eth_packets += 1;
        self.eth_bytes += bytes;

        let is_ipv6 = packet.src_addr.map(|ip| ip.is_ipv6()).unwrap_or(false);
        if packet.protocol == Protocol::Arp {
            self.arp_packets += 1;
            self.arp_bytes += bytes;
        } else if is_ipv6 {
            self.ip6_packets += 1;
            self.ip6_bytes += bytes;
        } else {
            self.ip4_packets += 1;
            self.ip4_bytes += bytes;
        }

        let is_tcp = matches!(
            packet.protocol,
            Protocol::Tcp
                | Protocol::Http
                | Protocol::Tls
                | Protocol::Ssh
                | Protocol::Ftp
                | Protocol::Smtp
                | Protocol::Imap
                | Protocol::Pop3
                | Protocol::Telnet
                | Protocol::Rdp
                | Protocol::WebSocket
                | Protocol::Http2
                | Protocol::Grpc
                | Protocol::Postgres
                | Protocol::Mysql
                | Protocol::Mongodb
                | Protocol::Redis
                | Protocol::Cassandra
                | Protocol::Modbus
                | Protocol::Dnp3
                | Protocol::Enip
                | Protocol::OpcUa
                | Protocol::Ntlm
        );
        let is_udp = matches!(
            packet.protocol,
            Protocol::Udp
                | Protocol::Dns
                | Protocol::Dhcp
                | Protocol::Ntp
                | Protocol::Mdns
                | Protocol::Snmp
                | Protocol::Quic
                | Protocol::Sip
                | Protocol::Rtp
                | Protocol::Rtcp
        );

        if is_tcp {
            self.tcp_packets += 1;
            self.tcp_bytes += bytes;
        } else if is_udp {
            self.udp_packets += 1;
            self.udp_bytes += bytes;
        } else if packet.protocol == Protocol::Icmp {
            self.icmp_packets += 1;
            self.icmp_bytes += bytes;
        }

        // Update per-protocol stats
        let proto = self
            .per_protocol
            .entry(packet.protocol.clone())
            .or_insert(ProtocolStats {
                total_packets: 0,
                total_bytes: 0,
            });
        proto.total_packets += 1;
        proto.total_bytes += bytes;

        // Track top talkers
        if let Some(src) = packet.src_addr {
            *self.sent_by_ip.entry(src).or_insert(0) += bytes;
        }
        if let Some(dst) = packet.dst_addr {
            *self.received_by_ip.entry(dst).or_insert(0) += bytes;
        }

        // Track DNS domains from summaries
        if packet.protocol == Protocol::Dns {
            if let Some(domain) = extract_domain_from_summary(&packet.summary) {
                *self.domain_counts.entry(domain).or_insert(0) += 1;
            }
        }
    }

    /// Advance the per-second bandwidth sampler. Call this once per app tick;
    /// it only records a sample when a full second has elapsed. Kept separate
    /// from [`snapshot`] so rendering (which may call `snapshot` several times
    /// per frame) never mutates the sampler.
    pub fn tick(&mut self) {
        let elapsed = self.last_second_check.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let bw = self.bytes_this_second as f64 / elapsed.as_secs_f64();
            self.bandwidth_samples.push(bw);
            if self.bandwidth_samples.len() > 60 {
                self.bandwidth_samples.remove(0);
            }
            self.bytes_this_second = 0;
            self.last_second_check = Instant::now();
        }
    }

    /// Total packets seen — a cheap read that avoids building a full snapshot.
    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let current_bw = {
            let elapsed = self.last_second_check.elapsed().as_secs_f64().max(0.001);
            self.bytes_this_second as f64 / elapsed
        };

        let avg_bw = if self.bandwidth_samples.is_empty() {
            0.0
        } else {
            self.bandwidth_samples.iter().sum::<f64>() / self.bandwidth_samples.len() as f64
        };

        let mut top_sent: Vec<(IpAddr, u64)> = self.sent_by_ip.clone().into_iter().collect();
        top_sent.sort_by_key(|k| std::cmp::Reverse(k.1));
        top_sent.truncate(10);

        let mut top_received: Vec<(IpAddr, u64)> =
            self.received_by_ip.clone().into_iter().collect();
        top_received.sort_by_key(|k| std::cmp::Reverse(k.1));
        top_received.truncate(10);

        let mut top_domains: Vec<(String, u64)> = self.domain_counts.clone().into_iter().collect();
        top_domains.sort_by_key(|k| std::cmp::Reverse(k.1));
        top_domains.truncate(10);

        // Build hierarchy tree
        let mut protocol_hierarchy = Vec::new();
        protocol_hierarchy.push(("Frame (Ethernet)".to_string(), self.eth_packets, self.eth_bytes));
        if self.arp_packets > 0 {
            protocol_hierarchy.push(("  └─ ARP".to_string(), self.arp_packets, self.arp_bytes));
        }
        if self.ip6_packets > 0 {
            protocol_hierarchy.push(("  └─ IPv6".to_string(), self.ip6_packets, self.ip6_bytes));
        }
        if self.ip4_packets > 0 {
            protocol_hierarchy.push(("  └─ IPv4".to_string(), self.ip4_packets, self.ip4_bytes));
            if self.tcp_packets > 0 {
                protocol_hierarchy.push(("      └─ TCP".to_string(), self.tcp_packets, self.tcp_bytes));
                for (proto, stats) in &self.per_protocol {
                    if proto != &Protocol::Tcp && matches!(
                        proto,
                        Protocol::Http
                            | Protocol::Tls
                            | Protocol::Ssh
                            | Protocol::Ftp
                            | Protocol::Smtp
                            | Protocol::Imap
                            | Protocol::Pop3
                            | Protocol::Telnet
                            | Protocol::Rdp
                            | Protocol::WebSocket
                            | Protocol::Http2
                            | Protocol::Grpc
                            | Protocol::Postgres
                            | Protocol::Mysql
                            | Protocol::Mongodb
                            | Protocol::Redis
                            | Protocol::Cassandra
                            | Protocol::Modbus
                            | Protocol::Dnp3
                            | Protocol::Enip
                            | Protocol::OpcUa
                            | Protocol::Ntlm
                    ) {
                        protocol_hierarchy.push((format!("          └─ {:?}", proto), stats.total_packets, stats.total_bytes));
                    }
                }
            }
            if self.udp_packets > 0 {
                protocol_hierarchy.push(("      └─ UDP".to_string(), self.udp_packets, self.udp_bytes));
                for (proto, stats) in &self.per_protocol {
                    if proto != &Protocol::Udp && matches!(
                        proto,
                        Protocol::Dns
                            | Protocol::Dhcp
                            | Protocol::Ntp
                            | Protocol::Mdns
                            | Protocol::Snmp
                            | Protocol::Quic
                            | Protocol::Sip
                            | Protocol::Rtp
                            | Protocol::Rtcp
                    ) {
                        protocol_hierarchy.push((format!("          └─ {:?}", proto), stats.total_packets, stats.total_bytes));
                    }
                }
            }
            if self.icmp_packets > 0 {
                protocol_hierarchy.push(("      └─ ICMP".to_string(), self.icmp_packets, self.icmp_bytes));
            }
        }

        StatsSnapshot {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            per_protocol: self.per_protocol.clone(),
            current_bandwidth: current_bw,
            average_bandwidth: avg_bw,
            top_talkers_sent: top_sent,
            top_talkers_received: top_received,
            top_domains,
            len_distribution: self.len_distribution,
            protocol_hierarchy,
        }
    }
}

fn extract_domain_from_summary(summary: &str) -> Option<String> {
    if let Some(rest) = summary.strip_prefix("DNS Query — ") {
        rest.split(" (").next().map(|s| s.to_string())
    } else if let Some(rest) = summary.strip_prefix("DNS Response — ") {
        rest.split(" → ").next().map(|s| s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_packet(
        protocol: Protocol,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        len: usize,
        summary: &str,
    ) -> Packet {
        Packet {
            timestamp: chrono::Utc::now(),
            src_addr: src_ip.map(|s| s.parse().unwrap()),
            dst_addr: dst_ip.map(|s| s.parse().unwrap()),
            src_port: None,
            dst_port: None,
            protocol,
            length: len,
            summary: summary.into(),
            data: vec![0u8; len].into(),
        }
    }

    #[test]
    fn record_counts_packets_and_bytes() {
        let mut engine = StatsEngine::new();
        let pkt = test_packet(
            Protocol::Tcp,
            Some("10.0.0.1"),
            Some("10.0.0.2"),
            100,
            "test",
        );
        engine.record_packet(&pkt);
        let snap = engine.snapshot();
        assert_eq!(snap.total_packets, 1);
        assert_eq!(snap.total_bytes, 100);
    }

    #[test]
    fn per_protocol_counts() {
        let mut engine = StatsEngine::new();
        engine.record_packet(&test_packet(Protocol::Tcp, None, None, 50, ""));
        engine.record_packet(&test_packet(Protocol::Udp, None, None, 30, ""));
        engine.record_packet(&test_packet(Protocol::Tcp, None, None, 20, ""));
        let snap = engine.snapshot();
        assert_eq!(snap.total_packets, 3);
        assert_eq!(
            snap.per_protocol.get(&Protocol::Tcp).unwrap().total_packets,
            2
        );
        assert_eq!(
            snap.per_protocol.get(&Protocol::Tcp).unwrap().total_bytes,
            70
        );
        assert_eq!(
            snap.per_protocol.get(&Protocol::Udp).unwrap().total_packets,
            1
        );
    }

    #[test]
    fn top_talkers() {
        let mut engine = StatsEngine::new();
        engine.record_packet(&test_packet(
            Protocol::Tcp,
            Some("10.0.0.1"),
            Some("10.0.0.2"),
            100,
            "",
        ));
        engine.record_packet(&test_packet(
            Protocol::Udp,
            Some("10.0.0.1"),
            Some("10.0.0.3"),
            200,
            "",
        ));
        engine.record_packet(&test_packet(
            Protocol::Tcp,
            Some("10.0.0.3"),
            Some("10.0.0.1"),
            50,
            "",
        ));
        let snap = engine.snapshot();
        // top sent: 10.0.0.1 = 300, 10.0.0.3 = 50
        assert_eq!(
            snap.top_talkers_sent[0].0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(snap.top_talkers_sent[0].1, 300);
        // top received: 10.0.0.2 = 100, 10.0.0.3 = 200, 10.0.0.1 = 50
        assert_eq!(
            snap.top_talkers_received[0].0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))
        );
        assert_eq!(snap.top_talkers_received[0].1, 200);
    }

    #[test]
    fn dns_domain_tracking() {
        let mut engine = StatsEngine::new();
        engine.record_packet(&test_packet(
            Protocol::Dns,
            None,
            None,
            50,
            "DNS Query — google.com (1)",
        ));
        engine.record_packet(&test_packet(
            Protocol::Dns,
            None,
            None,
            80,
            "DNS Response — google.com → 1.2.3.4 (1 answers)",
        ));
        engine.record_packet(&test_packet(
            Protocol::Tcp,
            None,
            None,
            30,
            "something else",
        ));
        let snap = engine.snapshot();
        assert_eq!(snap.top_domains.len(), 1);
        assert_eq!(snap.top_domains[0].0, "google.com");
        assert_eq!(snap.top_domains[0].1, 2);
    }

    #[test]
    fn empty_stats() {
        let engine = StatsEngine::new();
        let snap = engine.snapshot();
        assert_eq!(snap.total_packets, 0);
        assert_eq!(snap.total_bytes, 0);
        assert!(snap.top_talkers_sent.is_empty());
        assert!(snap.top_domains.is_empty());
    }
}
