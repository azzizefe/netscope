pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::net::IpAddr;

use crate::models::Protocol;

#[derive(Debug, Clone)]
pub struct DissectedResult {
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub summary: String,
}

pub fn dissect(data: &[u8]) -> DissectedResult {
    let eth = match ethernet::dissect_ethernet(data) {
        Some(e) => e,
        None => {
            return DissectedResult {
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown("failed to parse ethernet".into()),
                summary: "Malformed packet (cannot parse Ethernet header)".into(),
            };
        }
    };

    match eth.ethertype {
        etherparse::EtherType::ARP => arp::dissect_arp(&eth.payload),
        etherparse::EtherType::IPV4 => {
            let (src_ip, dst_ip, proto, payload) = ip::dissect_ipv4(&eth.payload);
            dispatch_transport((src_ip, dst_ip, proto), payload, eth.payload.len())
        }
        etherparse::EtherType::IPV6 => {
            let (src_ip, dst_ip, proto, payload) = ip::dissect_ipv6(&eth.payload);
            dispatch_transport((src_ip, dst_ip, proto), payload, eth.payload.len())
        }
        _ => DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Unknown(format!("ethertype 0x{:04x}", eth.ethertype.0)),
            summary: format!("Unknown L3 protocol (ethertype 0x{:04x})", eth.ethertype.0),
        },
    }
}

/// Human-readable names for IP protocol numbers we don't dissect further.
fn ip_protocol_name(p: u8) -> String {
    match p {
        2 => "IGMP".into(),
        47 => "GRE".into(),
        50 => "ESP (IPsec)".into(),
        51 => "AH (IPsec)".into(),
        89 => "OSPF".into(),
        132 => "SCTP".into(),
        other => format!("IP protocol {other}"),
    }
}

fn dispatch_transport(
    ip_result: (Option<IpAddr>, Option<IpAddr>, Option<u8>),
    payload: Vec<u8>,
    ip_len: usize,
) -> DissectedResult {
    let (src_ip, dst_ip, protocol_num) = ip_result;
    match protocol_num {
        Some(6) => tcp::dissect_tcp(src_ip, dst_ip, &payload),
        Some(17) => udp::dissect_udp(src_ip, dst_ip, &payload),
        Some(1) => icmp::dissect_icmp(src_ip, dst_ip, &payload, false),
        Some(58) => icmp::dissect_icmp(src_ip, dst_ip, &payload, true),
        Some(p) => {
            let name = ip_protocol_name(p);
            DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown(name.to_string()),
                summary: format!("{name} ({ip_len} bytes)"),
            }
        }
        None => DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Unknown("failed to parse IP".into()),
            summary: "Malformed IP header".into(),
        },
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use etherparse::*;

    /// Build an Ethernet + IPv4 + TCP packet with optional payload.
    /// Returns the raw bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn build_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        syn: bool,
        ack: bool,
        fin: bool,
        rst: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        let eth = Ethernet2Header {
            source: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            destination: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
            ether_type: EtherType::IPV4,
        };
        eth.write(&mut buf).unwrap();

        let ip = Ipv4Header::new(0, 64, IpNumber::TCP, src_ip, dst_ip).unwrap();
        ip.write(&mut buf).unwrap();

        let mut tcp = TcpHeader::new(src_port, dst_port, 0, 65535);
        tcp.syn = syn;
        tcp.ack = ack;
        tcp.fin = fin;
        tcp.rst = rst;
        tcp.write(&mut buf).unwrap();

        buf.extend_from_slice(payload);
        buf
    }

    /// Build an Ethernet + IPv4 + UDP packet with optional payload.
    pub fn build_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        let eth = Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: EtherType::IPV4,
        };
        eth.write(&mut buf).unwrap();

        let ip = Ipv4Header::new(0, 64, IpNumber::UDP, src_ip, dst_ip).unwrap();
        ip.write(&mut buf).unwrap();

        let udp = UdpHeader::without_ipv4_checksum(src_port, dst_port, payload.len()).unwrap();
        udp.write(&mut buf).unwrap();

        buf.extend_from_slice(payload);
        buf
    }

    /// Build an ARP packet (request or reply).
    pub fn build_arp_packet(
        operation: u16,
        sender_mac: &[u8; 6],
        sender_ip: &[u8; 4],
        target_mac: &[u8; 6],
        target_ip: &[u8; 4],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // Ethernet header
        let eth = Ethernet2Header {
            source: *sender_mac,
            destination: [0xff; 6],
            ether_type: EtherType::ARP,
        };
        eth.write(&mut buf).unwrap();

        // ARP body
        buf.extend_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
        buf.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
        buf.push(6); // hardware size
        buf.push(4); // protocol size
        buf.extend_from_slice(&operation.to_be_bytes());
        buf.extend_from_slice(sender_mac);
        buf.extend_from_slice(sender_ip);
        buf.extend_from_slice(target_mac);
        buf.extend_from_slice(target_ip);
        buf
    }

    /// Build a minimal DNS query payload.
    pub fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: ID + flags (query) + 1 question + 0 answers + 0 auth + 0 additional
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x00]); // answers: 0
        buf.extend_from_slice(&[0x00, 0x00]); // authority: 0
        buf.extend_from_slice(&[0x00, 0x00]); // additional: 0

        // Question: encoded domain name
        for part in domain.split('.') {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0x00); // end of domain name
        buf.extend_from_slice(&[0x00, 0x01]); // type: A
        buf.extend_from_slice(&[0x00, 0x01]); // class: IN
        buf
    }

    /// Build a minimal DNS response payload.
    pub fn build_dns_response(domain: &str, id: u16, answer_ip: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x81, 0x80]); // flags: response, no error
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x01]); // answers: 1
        buf.extend_from_slice(&[0x00, 0x00]); // authority: 0
        buf.extend_from_slice(&[0x00, 0x00]); // additional: 0

        // Question
        for part in domain.split('.') {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x01]); // type: A
        buf.extend_from_slice(&[0x00, 0x01]); // class: IN

        // Answer
        buf.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        buf.extend_from_slice(&[0x00, 0x01]); // type: A
        buf.extend_from_slice(&[0x00, 0x01]); // class: IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL: 60
        buf.extend_from_slice(&[0x00, 0x04]); // data length: 4
        buf.extend_from_slice(&answer_ip); // IP address
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn end_to_end_http_via_dissect() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            false,
            true,
            false,
            false,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        let result = dissect(&data);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(
            result.src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            result.dst_addr,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(result.summary, "HTTP GET / (HTTP/1.1)");
    }

    #[test]
    fn end_to_end_dns_via_dissect() {
        let dns_payload = build_dns_query("example.com", 0x5678);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns_payload);
        let result = dissect(&data);
        assert_eq!(result.protocol, Protocol::Dns);
        assert_eq!(result.summary, "DNS Query — example.com");
    }

    #[test]
    fn end_to_end_tls_via_dissect() {
        let mut tls_data = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        let mut hello = vec![0x01, 0x00, 0x00, 0x00];
        hello.extend_from_slice(&[0x03, 0x03]); // version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0x00); // no session id
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher suites
        hello.push(0x01);
        hello.push(0x00); // compression
        hello.extend_from_slice(&[0x00, 0x00]); // no extensions
                                                // Handshake length (3 bytes, big-endian) at bytes 1-3
        let hs_len = hello.len() - 4;
        hello[1] = ((hs_len >> 16) & 0xff) as u8;
        hello[2] = ((hs_len >> 8) & 0xff) as u8;
        hello[3] = (hs_len & 0xff) as u8;
        // Record length at bytes 3-4
        let record_len = hello.len();
        tls_data[3] = ((record_len >> 8) & 0xff) as u8;
        tls_data[4] = (record_len & 0xff) as u8;
        tls_data.extend_from_slice(&hello);

        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54321,
            443,
            false,
            true,
            false,
            false,
            &tls_data,
        );
        let result = dissect(&data);
        assert_eq!(result.protocol, Protocol::Tls);
    }

    #[test]
    fn end_to_end_arp_via_dissect() {
        let data = build_arp_packet(
            1,
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 168, 1, 1],
            &[0; 6],
            &[192, 168, 1, 2],
        );
        let result = dissect(&data);
        assert_eq!(result.protocol, Protocol::Arp);
        assert_eq!(
            result.src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            result.dst_addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
    }

    #[test]
    fn dispatch_empty_data() {
        let result = dissect(&[]);
        assert!(matches!(result.protocol, Protocol::Unknown(_)));
    }

    #[test]
    fn dispatch_garbage_data() {
        let garbage = (0..100).collect::<Vec<_>>();
        let result = dissect(&garbage);
        assert!(matches!(result.protocol, Protocol::Unknown(_)));
    }

    #[test]
    fn dispatch_random_garbage_never_panics() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut state = seed;
        for _ in 0..1000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = (state % 1500) as usize;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                data.push((state >> 40) as u8);
            }
            let result = dissect(&data);
            // Must never panic, always return a valid DissectedResult
            let _ = result.protocol;
        }
    }
}

/// Benchmark: measure throughput of dissect() with realistic packets.
///
/// Run with: `cargo test bench_dissect_throughput -- --nocapture`
#[cfg(test)]
mod bench {
    use super::*;
    use crate::dissectors::test_helpers::*;

    fn build_mixed_packets(count: usize) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(count);
        for i in 0..count {
            let pkt = match i % 5 {
                0 => build_tcp_packet(
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    12345,
                    80,
                    false,
                    true,
                    false,
                    false,
                    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ),
                1 => {
                    let dns = build_dns_query("example.com", i as u16);
                    build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns)
                }
                2 => {
                    let dns = build_dns_response("example.com", i as u16, [1, 2, 3, 4]);
                    build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 53, 54321, &dns)
                }
                3 => build_tcp_packet(
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    54321,
                    443,
                    true,
                    false,
                    false,
                    false,
                    &[],
                ),
                _ => build_arp_packet(1, &[0xaa; 6], &[192, 168, 1, 1], &[0; 6], &[192, 168, 1, 2]),
            };
            packets.push(pkt);
        }
        packets
    }

    #[test]
    fn bench_dissect_throughput() {
        const COUNT: usize = 10_000;
        let packets = build_mixed_packets(COUNT);

        // Warmup
        for pkt in &packets[..100] {
            let _ = dissect(pkt);
        }

        let start = std::time::Instant::now();
        let mut total = 0;
        for pkt in &packets {
            let result = dissect(pkt);
            total += match result.protocol {
                Protocol::Unknown(ref s) if s == "failed to parse ethernet" => 1,
                _ => 0,
            };
        }
        let elapsed = start.elapsed();
        let rate = COUNT as f64 / elapsed.as_secs_f64();

        println!(
            "Dissected {} packets in {:.2}s → {:.0} pkt/s ({} failures)",
            COUNT,
            elapsed.as_secs_f64(),
            rate,
            total
        );

        // Ensure we can handle at least 100k pps
        assert!(
            rate > 100_000.0,
            "Performance too low: {:.0} pkt/s (need > 100k)",
            rate
        );
    }
}
