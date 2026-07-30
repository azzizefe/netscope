// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use etherparse::*;
use std::fs::File;
use std::io::Write;

fn write_pcap_header(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&0xa1b2c3d4u32.to_be_bytes())?;
    w.write_all(&2u16.to_be_bytes())?;
    w.write_all(&4u16.to_be_bytes())?;
    w.write_all(&0i32.to_be_bytes())?;
    w.write_all(&0u32.to_be_bytes())?;
    w.write_all(&65535u32.to_be_bytes())?;
    w.write_all(&1u32.to_be_bytes())?;
    Ok(())
}

fn write_packet(w: &mut impl Write, data: &[u8], ts_sec: u32, ts_usec: u32) -> std::io::Result<()> {
    w.write_all(&ts_sec.to_be_bytes())?;
    w.write_all(&ts_usec.to_be_bytes())?;
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

fn build_tcp_pkt(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
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
    tcp.ack = true;
    tcp.write(&mut buf).unwrap();
    buf.extend_from_slice(payload);
    buf
}

fn build_udp_pkt(
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

fn build_arp_pkt(
    operation: u16,
    sender_mac: &[u8; 6],
    sender_ip: &[u8; 4],
    target_mac: &[u8; 6],
    target_ip: &[u8; 4],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let eth = Ethernet2Header {
        source: *sender_mac,
        destination: [0xff; 6],
        ether_type: EtherType::ARP,
    };
    eth.write(&mut buf).unwrap();
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x08, 0x00]);
    buf.push(6);
    buf.push(4);
    buf.extend_from_slice(&operation.to_be_bytes());
    buf.extend_from_slice(sender_mac);
    buf.extend_from_slice(sender_ip);
    buf.extend_from_slice(target_mac);
    buf.extend_from_slice(target_ip);
    buf
}

fn build_dns_query(domain: &str, id: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    for part in domain.split('.') {
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

fn build_dns_response(domain: &str, id: u16, answer_ip: [u8; 4]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x81, 0x80]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x00]);
    for part in domain.split('.') {
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0xc0, 0x0c]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    buf.extend_from_slice(&[0x00, 0x04]);
    buf.extend_from_slice(&answer_ip);
    buf
}

fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
    let mut tls = vec![0x16, 0x03, 0x03, 0x00, 0x00];
    let mut hello = vec![0x01, 0x00, 0x00, 0x00];
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    hello.push(0x01);
    hello.push(0x00);

    // SNI extension
    let hostname_bytes = hostname.as_bytes();
    let sni_list_len = 1 + 2 + hostname_bytes.len();
    let sni_ext_len = 2 + sni_list_len;
    let ext_len = 2 + sni_ext_len;
    hello.extend_from_slice(&(ext_len as u16).to_be_bytes());
    hello.extend_from_slice(&[0x00, 0x00]); // SNI type
    hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    hello.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    hello.push(0x00); // host_name type
    hello.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(hostname_bytes);

    let hs_len = hello.len() - 4;
    hello[1] = ((hs_len >> 16) & 0xff) as u8;
    hello[2] = ((hs_len >> 8) & 0xff) as u8;
    hello[3] = (hs_len & 0xff) as u8;
    let record_len = hello.len();
    tls[3] = ((record_len >> 8) & 0xff) as u8;
    tls[4] = (record_len & 0xff) as u8;
    tls.extend_from_slice(&hello);
    tls
}

fn main() -> std::io::Result<()> {
    let packets: Vec<(&str, Vec<u8>)> = vec![
        (
            "http_request",
            build_tcp_pkt(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                12345,
                80,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
        ),
        (
            "http_response",
            build_tcp_pkt(
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                80,
                12345,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            ),
        ),
        (
            "dns_query",
            build_udp_pkt(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                54321,
                53,
                &build_dns_query("example.com", 0x1234),
            ),
        ),
        (
            "dns_response",
            build_udp_pkt(
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                53,
                54321,
                &build_dns_response("example.com", 0x1234, [93, 184, 216, 34]),
            ),
        ),
        (
            "arp_request",
            build_arp_pkt(
                1,
                &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                &[192, 168, 1, 1],
                &[0; 6],
                &[192, 168, 1, 2],
            ),
        ),
        (
            "tls_handshake",
            build_tcp_pkt(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                54321,
                443,
                &build_tls_client_hello("example.com"),
            ),
        ),
        ("tcp_syn", {
            let mut buf = Vec::new();
            let eth = Ethernet2Header {
                source: [0; 6],
                destination: [0; 6],
                ether_type: EtherType::IPV4,
            };
            eth.write(&mut buf).unwrap();
            let ip = Ipv4Header::new(0, 64, IpNumber::TCP, [10, 0, 0, 1], [10, 0, 0, 2]).unwrap();
            ip.write(&mut buf).unwrap();
            let mut tcp = TcpHeader::new(12345, 80, 0, 65535);
            tcp.syn = true;
            tcp.write(&mut buf).unwrap();
            buf
        }),
    ];

    // Write mixed fixture
    let mut f = File::create("fixtures/mixed.pcap")?;
    write_pcap_header(&mut f)?;
    for (i, (_name, pkt)) in packets.iter().enumerate() {
        write_packet(&mut f, pkt, 1000000 + i as u32, 0)?;
    }
    println!("Created fixtures/mixed.pcap ({} packets)", packets.len());

    // Write individual fixtures
    for (name, pkt) in &packets {
        let pcap_path = format!("fixtures/{}.pcap", name);
        let mut f = File::create(&pcap_path)?;
        write_pcap_header(&mut f)?;
        write_packet(&mut f, pkt, 1000000, 0)?;
        println!("Created {}", pcap_path);
    }

    Ok(())
}
