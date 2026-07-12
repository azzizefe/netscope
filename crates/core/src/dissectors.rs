pub mod arp;
pub mod bacnet;
pub mod bgp;
pub mod cassandra;
pub mod coap;
pub mod dhcp;
pub mod dnp3;
pub mod dns;
pub mod enip;
pub mod ethernet;
pub mod ftp;
pub mod http;
pub mod http2;
pub mod icmp;
pub mod imap;
pub mod ip;
pub mod ipsec;
pub mod kerberos;
pub mod lacp;
pub mod ldap;
pub mod lldp;
pub mod modbus;
pub mod mongodb;
pub mod mpls;
pub mod mqtt;
pub mod mysql;
pub mod ntp;
pub mod opcua;
pub mod openvpn;
pub mod ospf;
pub mod pop3;
pub mod postgres;
pub mod radiotap;
pub mod radius;
pub mod rdp;
pub mod redis;
pub mod rtp;
pub mod sip;
pub mod smtp;
pub mod snmp;
pub mod ssh;
pub mod stp;
pub mod tcp;
pub mod telnet;
pub mod tls;
pub mod udp;
pub mod vxlan;
pub mod websocket;
pub mod wireguard;
pub mod wlan;

use std::net::IpAddr;

use crate::models::Protocol;

/// First line of a text protocol payload (up to CR/LF), lossily decoded and
/// trimmed. Shared by the line-oriented dissectors (FTP, SMTP, IMAP, POP3).
/// Uses SIMD-accelerated `memchr` for the line-end scan (ROADMAP §4.1).
pub(crate) fn first_text_line(payload: &[u8]) -> String {
    let end = memchr::memchr2(b'\r', b'\n', payload).unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).trim().to_string()
}

/// First `max` bytes of `s`, backed off to a char boundary so the slice is
/// always valid. Used to cap header scans without risking a mid-char panic.
pub(crate) fn head_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Truncate a display string to `max` characters, adding an ellipsis when cut.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[derive(Debug, Clone)]
pub struct DissectedResult {
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub summary: String,
}

// libpcap data-link types (DLT_*) we branch on. Everything else is treated
// as Ethernet, which is the overwhelmingly common case.
const DLT_EN10MB: i32 = 1;
const DLT_IEEE802_11: i32 = 105;
const DLT_IEEE802_11_RADIO: i32 = 127;

/// Entry point that respects the capture's link-layer type. Ethernet captures
/// (the default) go through [`dissect`]; Wi-Fi captures — raw 802.11 or
/// radiotap-prefixed (monitor mode) — go through the WLAN dissector.
pub fn dissect_linktype(data: &[u8], linktype: i32) -> DissectedResult {
    match linktype {
        DLT_IEEE802_11_RADIO => wlan::dissect_radiotap(data),
        DLT_IEEE802_11 => wlan::dissect_80211(data, None),
        DLT_EN10MB => dissect(data),
        _ => dissect(data),
    }
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

    dispatch_l3(eth.ethertype.0, &eth.payload, 0)
}

// EtherType values handled below the Ethernet header. Named here so the VLAN
// unwrapping stays readable.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100; // 802.1Q
const ETHERTYPE_QINQ_88A8: u16 = 0x88A8; // 802.1ad service tag
const ETHERTYPE_QINQ_9100: u16 = 0x9100; // legacy double-tag
const ETHERTYPE_LLDP: u16 = 0x88CC; // Link Layer Discovery Protocol
const ETHERTYPE_SLOW: u16 = 0x8809; // 802.3 slow protocols (LACP/Marker/OAM)
const ETHERTYPE_MPLS_UCAST: u16 = 0x8847; // MPLS unicast
const ETHERTYPE_MPLS_MCAST: u16 = 0x8848; // MPLS multicast
                                          // EtherType values at or below this are actually 802.3 length fields (LLC).
const ETHERTYPE_MAX_LENGTH: u16 = 0x05DC; // 1500

/// Dispatch on the L3 EtherType. Recurses through VLAN (802.1Q / QinQ) tags,
/// unwrapping each 4-byte tag and re-dispatching on the inner EtherType so a
/// tagged frame still reaches its IP/ARP dissector. `vlan_depth` caps the
/// recursion (2 tags is the practical maximum: QinQ).
fn dispatch_l3(ethertype: u16, payload: &[u8], vlan_depth: u8) -> DissectedResult {
    match ethertype {
        ETHERTYPE_ARP => arp::dissect_arp(payload),
        ETHERTYPE_IPV4 => {
            let (src_ip, dst_ip, proto, inner) = ip::dissect_ipv4(payload);
            dispatch_transport((src_ip, dst_ip, proto), inner, payload.len())
        }
        ETHERTYPE_IPV6 => {
            let (src_ip, dst_ip, proto, inner) = ip::dissect_ipv6(payload);
            dispatch_transport((src_ip, dst_ip, proto), inner, payload.len())
        }
        ETHERTYPE_LLDP => lldp::dissect_lldp(payload),
        ETHERTYPE_SLOW => lacp::dissect_slow(payload),
        ETHERTYPE_MPLS_UCAST | ETHERTYPE_MPLS_MCAST => dissect_mpls(payload, vlan_depth),
        // 802.3 length-form frames carry an LLC header; the STP BPDU is the one
        // we recognise there (DSAP/SSAP 0x42).
        et if et <= ETHERTYPE_MAX_LENGTH && stp::is_stp(payload) => stp::dissect_stp(payload),
        ETHERTYPE_VLAN | ETHERTYPE_QINQ_88A8 | ETHERTYPE_QINQ_9100 if vlan_depth < 2 => {
            // 802.1Q tag: 2 bytes TCI (PCP/DEI/VID) + 2 bytes inner EtherType.
            if payload.len() < 4 {
                return DissectedResult {
                    src_addr: None,
                    dst_addr: None,
                    src_port: None,
                    dst_port: None,
                    protocol: Protocol::Unknown("truncated VLAN tag".into()),
                    summary: "Malformed VLAN tag (too short)".into(),
                };
            }
            let vlan_id = u16::from_be_bytes([payload[0], payload[1]]) & 0x0FFF;
            let inner_ethertype = u16::from_be_bytes([payload[2], payload[3]]);
            let mut inner = dispatch_l3(inner_ethertype, &payload[4..], vlan_depth + 1);
            inner.summary = format!("VLAN {vlan_id} · {}", inner.summary);
            inner
        }
        other => DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Unknown(format!("ethertype 0x{other:04x}")),
            summary: format!("Unknown L3 protocol (ethertype 0x{other:04x})"),
        },
    }
}

/// Unwrap an MPLS label stack and dissect the inner packet, relabelling the
/// result as MPLS with the top label. Only IP payloads are unwrapped further;
/// other inner protocols (e.g. Ethernet pseudowires) are reported generically.
fn dissect_mpls(payload: &[u8], vlan_depth: u8) -> DissectedResult {
    let malformed = || DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown("truncated MPLS".into()),
        summary: "Malformed MPLS label stack".into(),
    };
    let stack = match mpls::parse(payload) {
        Some(s) => s,
        None => return malformed(),
    };
    let inner = &payload[stack.inner_offset..];
    let label_note = if stack.label_count > 1 {
        format!(
            "MPLS label {} (+{} more, TTL {})",
            stack.top_label,
            stack.label_count - 1,
            stack.top_ttl
        )
    } else {
        format!("MPLS label {} (TTL {})", stack.top_label, stack.top_ttl)
    };
    // Peek the inner IP version and recurse; keep the inner addresses/ports but
    // present it under the MPLS protocol with the label prefixed.
    let inner_ethertype = match inner.first().map(|b| b >> 4) {
        Some(4) => Some(ETHERTYPE_IPV4),
        Some(6) => Some(ETHERTYPE_IPV6),
        _ => None,
    };
    match inner_ethertype {
        Some(et) => {
            let mut r = dispatch_l3(et, inner, vlan_depth);
            r.protocol = Protocol::Mpls;
            r.summary = format!("{label_note} · {}", r.summary);
            r
        }
        None => DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Mpls,
            summary: format!("{label_note} · {} bytes payload", inner.len()),
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
        // IPsec ESP/AH carry an SPI in the clear (ROADMAP §3.7).
        Some(50) => ipsec::dissect_esp(src_ip, dst_ip, &payload),
        Some(51) => ipsec::dissect_ah(src_ip, dst_ip, &payload),
        // OSPF interior routing (ROADMAP §3.3).
        Some(89) => ospf::dissect_ospf(src_ip, dst_ip, &payload),
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

        let payload_len = (20 + payload.len()) as u16; // TCP header + payload
        let ip = Ipv4Header::new(payload_len, 64, IpNumber::TCP, src_ip, dst_ip).unwrap();
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

        let payload_len = (8 + payload.len()) as u16; // UDP header + payload
        let ip = Ipv4Header::new(payload_len, 64, IpNumber::UDP, src_ip, dst_ip).unwrap();
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

    /// Build a bare Ethernet II frame with a chosen EtherType and payload.
    fn build_eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]); // dst (multicast)
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        buf.extend_from_slice(&ethertype.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn end_to_end_lldp_via_dissect() {
        // Chassis ID + Port ID + TTL + System Name TLVs behind EtherType 0x88CC.
        let mut tlvs = Vec::new();
        tlvs.extend_from_slice(&[0x02, 0x07, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // chassis
        tlvs.extend_from_slice(&[0x04, 0x06, 0x05, b'G', b'i', b'0', b'/', b'1']); // port
        tlvs.extend_from_slice(&[0x06, 0x02, 0x00, 0x78]); // TTL
        tlvs.extend_from_slice(&[0x0a, 0x06, b's', b'w', b'-', b'c', b'o', b'r']); // system name
        let frame = build_eth_frame(0x88CC, &tlvs);
        let r = dissect(&frame);
        assert_eq!(r.protocol, Protocol::Lldp);
        assert!(r.summary.starts_with("LLDP — sw-cor port Gi0/1"));
    }

    #[test]
    fn end_to_end_mpls_unwraps_inner_ip() {
        // MPLS label 16 (bottom-of-stack), TTL 64, wrapping an IPv4/UDP DNS query.
        let dns = build_dns_query("example.com", 0x1234);
        let udp_pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, &dns);
        let inner_ip = &udp_pkt[14..]; // strip the inner packet's own Ethernet header
        let mut mpls = vec![0x00, 0x01, 0x01, 0x40]; // label 16, S=1, TTL 64
        mpls.extend_from_slice(inner_ip);
        let frame = build_eth_frame(0x8847, &mpls);
        let r = dissect(&frame);
        assert_eq!(r.protocol, Protocol::Mpls);
        assert!(r.summary.starts_with("MPLS label 16 (TTL 64) · "));
        assert!(r.summary.contains("example.com"));
    }

    #[test]
    fn end_to_end_bgp_via_dissect() {
        // BGP KEEPALIVE (marker + length 19 + type 4) to TCP 179.
        let mut bgp = vec![0xff; 16];
        bgp.extend_from_slice(&19u16.to_be_bytes());
        bgp.push(4);
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            179,
            false,
            true,
            false,
            false,
            &bgp,
        );
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Bgp);
        assert_eq!(r.summary, "BGP KEEPALIVE");
    }

    #[test]
    fn end_to_end_modbus_via_dissect() {
        // Modbus Read Holding Registers to TCP 502.
        let mut mb = Vec::new();
        mb.extend_from_slice(&1u16.to_be_bytes()); // transaction
        mb.extend_from_slice(&0u16.to_be_bytes()); // protocol id
        mb.extend_from_slice(&6u16.to_be_bytes()); // length
        mb.push(1); // unit
        mb.push(3); // function: read holding registers
        mb.extend_from_slice(&[0x00, 0x00, 0x00, 0x0a]);
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            502,
            false,
            true,
            false,
            false,
            &mb,
        );
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Modbus);
        assert!(r.summary.contains("Read Holding Registers"));
    }

    #[test]
    fn end_to_end_ospf_via_dissect() {
        // OSPF Hello (IP protocol 89) built on an IPv4 packet.
        let mut ospf = vec![2, 1, 0x00, 0x2c]; // v2, Hello, length
        ospf.extend_from_slice(&[10, 0, 0, 1]); // router id
        ospf.extend_from_slice(&[0, 0, 0, 0]); // area id
        ospf.extend_from_slice(&[0u8; 12]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        buf.extend_from_slice(&0x0800u16.to_be_bytes());
        // Minimal IPv4 header (20 bytes), protocol 89 (OSPF).
        let total_len = (20 + ospf.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 89, 0x00, 0x00]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[224, 0, 0, 5]);
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&ospf);
        let r = dissect(&buf);
        assert_eq!(r.protocol, Protocol::Ospf);
        assert!(r.summary.starts_with("OSPFv2 Hello — router 10.0.0.1"));
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
