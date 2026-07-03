use std::net::IpAddr;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Http,
    Tls,
    Icmp,
    Arp,
    Unknown(String),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Tls => write!(f, "TLS"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Arp => write!(f, "ARP"),
            Protocol::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

/// Format an address/port pair for display. IPv6 addresses are wrapped
/// in brackets (`[::1]:443`) so the port separator stays unambiguous.
pub fn format_endpoint(addr: IpAddr, port: Option<u16>) -> String {
    match (addr, port) {
        (IpAddr::V6(v6), Some(p)) => format!("[{v6}]:{p}"),
        (addr, Some(p)) => format!("{addr}:{p}"),
        (addr, None) => addr.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub length: usize,
    pub summary: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub packets: Vec<Packet>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl ConnectionInfo {
    pub fn duration(&self) -> chrono::Duration {
        self.end_time - self.start_time
    }

    pub fn byte_count(&self) -> usize {
        self.packets.iter().map(|p| p.length).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_endpoint_ipv4() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(format_endpoint(ip, Some(443)), "192.168.1.5:443");
        assert_eq!(format_endpoint(ip, None), "192.168.1.5");
    }

    #[test]
    fn format_endpoint_ipv6_bracketed() {
        let ip: IpAddr = "2600:1901:0:3084::".parse().unwrap();
        assert_eq!(format_endpoint(ip, Some(443)), "[2600:1901:0:3084::]:443");
        assert_eq!(format_endpoint(ip, None), "2600:1901:0:3084::");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Dns.to_string(), "DNS");
        assert_eq!(Protocol::Http.to_string(), "HTTP");
        assert_eq!(Protocol::Tls.to_string(), "TLS");
        assert_eq!(Protocol::Icmp.to_string(), "ICMP");
        assert_eq!(Protocol::Arp.to_string(), "ARP");
        assert_eq!(
            Protocol::Unknown("test".into()).to_string(),
            "Unknown(test)"
        );
    }

    #[test]
    fn protocol_equality() {
        assert_eq!(Protocol::Tcp, Protocol::Tcp);
        assert_ne!(Protocol::Tcp, Protocol::Udp);
        assert_eq!(Protocol::Unknown("a".into()), Protocol::Unknown("a".into()));
        assert_ne!(Protocol::Unknown("a".into()), Protocol::Unknown("b".into()));
    }

    #[test]
    fn packet_construction() {
        let ts: DateTime<Utc> = Utc::now();
        let pkt = Packet {
            timestamp: ts,
            src_addr: Some("192.168.1.1".parse().unwrap()),
            dst_addr: Some("192.168.1.2".parse().unwrap()),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            length: 100,
            summary: "TCP test".into(),
            data: vec![0u8; 100],
        };
        assert_eq!(pkt.src_port, Some(12345));
        assert_eq!(pkt.dst_port, Some(80));
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.length, 100);
        assert_eq!(pkt.summary, "TCP test");
    }

    #[test]
    fn connection_info_duration() {
        let ts1: DateTime<Utc> = "2024-01-01T00:00:00Z".parse().unwrap();
        let ts2: DateTime<Utc> = "2024-01-01T00:00:05Z".parse().unwrap();

        let pkt = Packet {
            timestamp: ts1,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Tcp,
            length: 50,
            summary: String::new(),
            data: Vec::new(),
        };

        let info = ConnectionInfo {
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.0.2".parse().unwrap(),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            packets: vec![pkt.clone(), pkt],
            start_time: ts1,
            end_time: ts2,
        };

        assert_eq!(info.duration().num_seconds(), 5);
        assert_eq!(info.byte_count(), 100);
    }
}
