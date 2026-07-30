// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared packet builders for the benchmarks (ROADMAP §4.4).
//!
//! Benches compile as separate crates, so the library's `#[cfg(test)]`
//! `test_helpers` aren't visible here — these builders mirror them using the
//! same `etherparse` writers, producing byte-identical frames.

#![allow(dead_code)] // each bench uses its own subset

use etherparse::*;

/// Ethernet + IPv4 + TCP frame with the given payload.
pub fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    Ethernet2Header {
        source: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        destination: [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        ether_type: EtherType::IPV4,
    }
    .write(&mut buf)
    .unwrap();
    let ip = Ipv4Header::new(
        (20 + payload.len()) as u16,
        64,
        IpNumber::TCP,
        src_ip,
        dst_ip,
    )
    .unwrap();
    ip.write(&mut buf).unwrap();
    let mut tcp = TcpHeader::new(src_port, dst_port, 0, 65535);
    tcp.syn = syn;
    tcp.ack = ack;
    tcp.write(&mut buf).unwrap();
    buf.extend_from_slice(payload);
    buf
}

/// Ethernet + IPv4 + UDP frame with the given payload.
pub fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    Ethernet2Header {
        source: [0; 6],
        destination: [0; 6],
        ether_type: EtherType::IPV4,
    }
    .write(&mut buf)
    .unwrap();
    let ip = Ipv4Header::new(
        (8 + payload.len()) as u16,
        64,
        IpNumber::UDP,
        src_ip,
        dst_ip,
    )
    .unwrap();
    ip.write(&mut buf).unwrap();
    let udp = UdpHeader::without_ipv4_checksum(src_port, dst_port, payload.len()).unwrap();
    udp.write(&mut buf).unwrap();
    buf.extend_from_slice(payload);
    buf
}

/// Minimal DNS A-record query for `domain`.
pub fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for part in domain.split('.') {
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    buf
}

/// ARP request frame.
pub fn build_arp_packet(sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut buf = Vec::new();
    Ethernet2Header {
        source: [0xaa; 6],
        destination: [0xff; 6],
        ether_type: EtherType::ARP,
    }
    .write(&mut buf)
    .unwrap();
    buf.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    buf.extend_from_slice(&[0xaa; 6]);
    buf.extend_from_slice(&sender_ip);
    buf.extend_from_slice(&[0x00; 6]);
    buf.extend_from_slice(&target_ip);
    buf
}

/// The traffic mix every benchmark agrees on: HTTP request, DNS query,
/// TLS-port payload, bare TCP SYN, ARP — weighted towards the hot TCP path.
pub fn build_mixed_packets(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| match i % 5 {
            0 => build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                12345,
                80,
                false,
                true,
                b"GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n",
            ),
            1 => {
                let dns = build_dns_query("example.com", i as u16);
                build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns)
            }
            2 => build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                54321,
                443,
                false,
                true,
                &[0x17, 0x03, 0x03, 0x00, 0x40], // TLS application data header
            ),
            3 => build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 443, true, false, &[]),
            _ => build_arp_packet([192, 168, 1, 1], [192, 168, 1, 2]),
        })
        .collect()
}
