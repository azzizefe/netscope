// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
pub mod aarp;
pub mod aerospike;
pub mod afp;
pub mod amqp;
pub mod arp;
pub mod atalk;
pub mod avtp;
pub mod babel;
pub mod bacnet;
pub mod beanstalk;
pub mod beats;
pub mod bfd;
pub mod bgp;
pub mod bittorrent;
pub mod bluetooth;
pub mod bmp;
pub mod bolt;
pub mod can;
pub mod capwap;
pub mod cassandra;
pub mod cdp;
pub mod clamav;
pub mod cldap;
pub mod clickhouse;
pub mod coap;
pub mod collectd;
pub mod dccp;
pub mod dcerpc;
pub mod dhcp;
pub mod dhcpv6;
pub mod dht;
pub mod diameter;
pub mod dicom;
pub mod dnp3;
pub mod dns;
pub mod doip;
pub mod dtls;
pub mod dtp;
pub mod eap;
pub mod eapol;
pub mod edonkey;
pub mod eigrp;
pub mod elasticsearch;
pub mod enip;
pub mod ethercat;
pub mod ethernet;
pub mod fcoe;
pub mod finger;
pub mod fix;
pub mod fluentd;
pub mod ftp;
pub mod ganglia;
pub mod gearman;
pub mod gelf;
pub mod geneve;
pub mod git;
pub mod glbp;
pub mod gnutella;
pub mod goose;
pub mod gopher;
pub mod graphite;
pub mod gre;
pub mod gtp;
pub mod gtpprime;
pub mod gvcp;
pub mod hadooprpc;
pub mod hartip;
pub mod hl7;
pub mod hsrp;
pub mod http;
pub mod http2;
pub mod ica;
pub mod icmp;
pub mod ident;
pub mod iec104;
pub mod igmp;
pub mod imap;
pub mod influxdb;
pub mod ip;
pub mod ipp;
pub mod ipsec;
pub mod ipx;
pub mod irc;
pub mod isakmp;
pub mod iscsi;
pub mod jaeger;
pub mod kafka;
pub mod kerberos;
pub mod knxip;
pub mod l2tp;
pub mod lacp;
pub mod ldap;
pub mod ldp;
pub mod lldp;
pub mod lpd;
pub mod macsec;
pub mod managesieve;
pub mod matter;
pub mod megaco;
pub mod memcached;
pub mod mgcp;
pub mod minecraft;
pub mod mms;
pub mod modbus;
pub mod mongodb;
pub mod mpls;
pub mod mqtt;
pub mod mqttsn;
pub mod msrp;
pub mod mumble;
pub mod mysql;
pub mod nats;
pub mod nbds;
pub mod nbns;
pub mod ndmp;
pub mod netflow;
pub mod nntp;
pub mod nrpe;
pub mod nsq;
pub mod ntlm;
pub mod ntp;
pub mod opcua;
pub mod openflow;
pub mod openvpn;
pub mod openwire;
pub mod ospf;
pub mod pagp;
pub mod pcoip;
pub mod pfcp;
pub mod pim;
pub mod pop3;
pub mod postgres;
pub mod powerlink;
pub mod pppoe;
pub mod pptp;
pub mod profinet;
pub mod ptp;
pub mod pulsar;
pub mod qpack;
pub mod radiotap;
pub mod radius;
pub mod radmin;
pub mod rarp;
pub mod rdp;
pub mod redis;
pub mod relp;
pub mod rethinkdb;
pub mod rexec;
pub mod rfb;
pub mod rip;
pub mod rlogin;
pub mod rmcp;
pub mod rpc;
pub mod rpkirtr;
pub mod rsh;
pub mod rsvp;
pub mod rsync;
pub mod rtmp;
pub mod rtp;
pub mod rtps;
pub mod rtsp;
pub mod s7comm;
pub mod sane;
pub mod sctp;
pub mod sercos;
pub mod sflow;
pub mod sip;
pub mod skinny;
pub mod sll;
pub mod smb;
pub mod smpp;
pub mod smtp;
pub mod snap;
pub mod snmp;
pub mod socks;
pub mod someip;
pub mod source_query;
pub mod spamd;
pub mod spice;
pub mod srt;
pub mod ssdp;
pub mod ssh;
pub mod statsd;
pub mod stomp;
pub mod stp;
pub mod stun;
pub mod sv;
pub mod svn;
pub mod syslog;
pub mod tacacs;
pub mod tcp;
pub mod tcp_analysis;
pub mod tds;
pub mod telnet;
pub mod teredo;
pub mod tftp;
pub mod tls;
pub mod udld;
pub mod udp;
pub mod usb;
pub mod vrrp;
pub mod vtp;
pub mod vxlan;
pub mod wccp;
pub mod websocket;
pub mod whois;
pub mod wireguard;
pub mod wlan;
pub mod wol;
pub mod wsd;
pub mod x11;
pub mod xcp;
pub mod xmpp;
pub mod zabbix;
pub mod zigbee;
pub mod zmtp;
pub mod zookeeper;

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
const DLT_LINUX_SLL: i32 = 113; // Linux cooked capture (tcpdump -i any)
const DLT_LINUX_SLL2: i32 = 276;
const DLT_BT_HCI_H4: i32 = 187; // Bluetooth HCI UART transport
const DLT_BT_HCI_H4_WITH_PHDR: i32 = 201; // …with a direction pseudo-header
const DLT_USB_LINUX: i32 = 189; // usbmon, 48-byte header
const DLT_USB_LINUX_MMAPPED: i32 = 220; // usbmon, 64-byte header
const DLT_CAN_SOCKETCAN: i32 = 227; // SocketCAN (can0/vcan0)
const DLT_USBPCAP: i32 = 249; // Windows USBPcap
const DLT_IEEE802_15_4: i32 = 195; // IEEE 802.15.4 Wireless PAN (Zigbee)

/// Entry point that respects the capture's link-layer type. Ethernet captures
/// (the default) go through [`dissect`]; Wi-Fi, Linux-cooked (remote
/// `-i any`), USB, Bluetooth-HCI and CAN captures each take their own
/// link-layer path.
pub fn dissect_linktype(data: &[u8], linktype: i32) -> DissectedResult {
    match linktype {
        DLT_IEEE802_11_RADIO => wlan::dissect_radiotap(data),
        DLT_IEEE802_11 => wlan::dissect_80211(data, None),
        DLT_LINUX_SLL => sll::dissect_sll(data),
        DLT_LINUX_SLL2 => sll::dissect_sll2(data),
        DLT_BT_HCI_H4 => bluetooth::dissect_hci_h4(data),
        DLT_BT_HCI_H4_WITH_PHDR => bluetooth::dissect_hci_with_phdr(data),
        DLT_USB_LINUX | DLT_USB_LINUX_MMAPPED => usb::dissect_usb_linux(data),
        DLT_USBPCAP => usb::dissect_usbpcap(data),
        DLT_CAN_SOCKETCAN => can::dissect_can(data),
        DLT_IEEE802_15_4 => zigbee::dissect_ieee802154(data),
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
const ETHERTYPE_PPPOE_DISC: u16 = 0x8863; // PPPoE discovery stage
const ETHERTYPE_PPPOE_SESS: u16 = 0x8864; // PPPoE session stage
const ETHERTYPE_EAPOL: u16 = 0x888E; // 802.1X port authentication (EAPOL)
const ETHERTYPE_PROFINET: u16 = 0x8892; // PROFINET real-time industrial
const ETHERTYPE_WOL: u16 = 0x0842; // Wake-on-LAN magic packet
const ETHERTYPE_IPX: u16 = 0x8137; // Novell NetWare IPX
const ETHERTYPE_ATALK: u16 = 0x809B; // AppleTalk DDP
const ETHERTYPE_AARP: u16 = 0x80F3; // AppleTalk ARP
const ETHERTYPE_GOOSE: u16 = 0x88B8; // IEC 61850 GOOSE substation events
const ETHERTYPE_PTP: u16 = 0x88F7; // IEEE 1588 Precision Time Protocol
const ETHERTYPE_AVTP: u16 = 0x22F0; // IEEE 1722 Audio/Video Transport
const ETHERTYPE_SV: u16 = 0x88BA; // IEC 61850-9-2 Sampled Values
const ETHERTYPE_POWERLINK: u16 = 0x88AB; // Ethernet POWERLINK real-time
const ETHERTYPE_SERCOS: u16 = 0x88CD; // SERCOS III motion control
const ETHERTYPE_RARP: u16 = 0x8035; // Reverse ARP
const ETHERTYPE_ETHERCAT: u16 = 0x88A4; // EtherCAT industrial fieldbus
const ETHERTYPE_MACSEC: u16 = 0x88E5; // 802.1AE MACsec link encryption
const ETHERTYPE_FCOE: u16 = 0x8906; // Fibre Channel over Ethernet
const ETHERTYPE_MPLS_UCAST: u16 = 0x8847; // MPLS unicast
const ETHERTYPE_MPLS_MCAST: u16 = 0x8848; // MPLS multicast
                                          // EtherType values at or below this are actually 802.3 length fields (LLC).
const ETHERTYPE_MAX_LENGTH: u16 = 0x05DC; // 1500

/// Dispatch on the L3 EtherType. Recurses through VLAN (802.1Q / QinQ) tags,
/// unwrapping each 4-byte tag and re-dispatching on the inner EtherType so a
/// tagged frame still reaches its IP/ARP dissector. `vlan_depth` caps the
/// recursion (2 tags is the practical maximum: QinQ).
pub(crate) fn dispatch_l3(ethertype: u16, payload: &[u8], vlan_depth: u8) -> DissectedResult {
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
        ETHERTYPE_PPPOE_DISC => pppoe::dissect_pppoe(payload, false),
        ETHERTYPE_PPPOE_SESS => pppoe::dissect_pppoe(payload, true),
        ETHERTYPE_EAPOL => eapol::dissect_eapol(payload),
        ETHERTYPE_PROFINET => profinet::dissect_profinet(payload),
        ETHERTYPE_WOL => wol::dissect_wol(payload),
        ETHERTYPE_GOOSE => goose::dissect_goose(payload),
        ETHERTYPE_PTP => ptp::dissect_ptp_l2(payload),
        ETHERTYPE_AVTP => avtp::dissect_avtp(payload),
        ETHERTYPE_SV => sv::dissect_sv(payload),
        ETHERTYPE_POWERLINK => powerlink::dissect_powerlink(payload),
        ETHERTYPE_SERCOS => sercos::dissect_sercos(payload),
        ETHERTYPE_RARP => rarp::dissect_rarp(payload),
        ETHERTYPE_ETHERCAT => ethercat::dissect_ethercat(payload),
        ETHERTYPE_MACSEC => macsec::dissect_macsec(payload),
        ETHERTYPE_FCOE => fcoe::dissect_fcoe(payload),
        ETHERTYPE_MPLS_UCAST | ETHERTYPE_MPLS_MCAST => dissect_mpls(payload, vlan_depth),
        // 802.3 length-form frames carry an LLC header; the STP BPDU is the one
        // we recognise there (DSAP/SSAP 0x42).
        ETHERTYPE_IPX => ipx::dissect_ipx(payload),
        ETHERTYPE_ATALK => atalk::dissect_atalk(payload),
        ETHERTYPE_AARP => aarp::dissect_aarp(payload),
        et if et <= ETHERTYPE_MAX_LENGTH && stp::is_stp(payload) => stp::dissect_stp(payload),
        // Other 802.3 length-form frames carry an LLC header; when it is SNAP,
        // the vendor OUI + protocol id select a dissector (Cisco's CDP, VTP,
        // DTP, PAgP and UDLD all live there).
        et if et <= ETHERTYPE_MAX_LENGTH => match snap::dissect_snap(payload) {
            Some(r) => r,
            None => DissectedResult {
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown(format!("802.3 LLC frame (length {et})")),
                summary: format!("IEEE 802.3 LLC frame ({et} bytes)"),
            },
        },
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
        // IGMP multicast group membership, GRE tunnels and SCTP transport all
        // ride directly on IP (protocols 2, 47 and 132).
        Some(2) => igmp::dissect_igmp(src_ip, dst_ip, &payload),
        Some(47) => gre::dissect_gre(src_ip, dst_ip, &payload),
        Some(132) => sctp::dissect_sctp(src_ip, dst_ip, &payload),
        Some(33) => dccp::dissect_dccp(src_ip, dst_ip, &payload),
        Some(46) => rsvp::dissect_rsvp(src_ip, dst_ip, &payload),
        // Interior routing (EIGRP 88, PIM 103) and gateway redundancy (VRRP 112).
        Some(88) => eigrp::dissect_eigrp(src_ip, dst_ip, &payload),
        Some(103) => pim::dissect_pim(src_ip, dst_ip, &payload),
        Some(112) => vrrp::dissect_vrrp(src_ip, dst_ip, &payload),
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

    /// TCP control flags for [`build_tcp_packet`]. `Default` is all-false.
    #[derive(Default, Clone, Copy)]
    pub struct TcpFlags {
        pub syn: bool,
        pub ack: bool,
        pub fin: bool,
        pub rst: bool,
    }

    /// Build an Ethernet + IPv4 + TCP packet with optional payload.
    /// Returns the raw bytes.
    pub fn build_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
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
        tcp.syn = flags.syn;
        tcp.ack = flags.ack;
        tcp.fin = flags.fin;
        tcp.rst = flags.rst;
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
        super::tcp::clear_tcp_reassembler();
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            51928,
            80,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
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
            TcpFlags {
                ack: true,
                ..Default::default()
            },
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
            TcpFlags {
                ack: true,
                ..Default::default()
            },
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
            TcpFlags {
                ack: true,
                ..Default::default()
            },
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
    fn end_to_end_syslog_via_dissect() {
        // Syslog PRI <34> (facility 4, severity 2 = Critical) to UDP 514.
        let data = build_udp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            40000,
            514,
            b"<34>disk failing",
        );
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Syslog);
        assert!(r.summary.contains("Critical"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_stun_via_dissect() {
        // STUN Binding Request (with the magic cookie) to UDP 3478.
        let mut stun = vec![0x00, 0x01, 0x00, 0x00];
        stun.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        stun.extend_from_slice(&[0u8; 12]);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 3478, &stun);
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Stun);
        assert_eq!(r.summary, "STUN Binding Request");
    }

    #[test]
    fn end_to_end_rtsp_via_dissect() {
        super::tcp::clear_tcp_reassembler();
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            40000,
            554,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            b"OPTIONS rtsp://cam/stream RTSP/1.0\r\n",
        );
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Rtsp);
        assert!(r.summary.starts_with("RTSP OPTIONS"), "{}", r.summary);
    }

    /// Build Ethernet + a minimal 20-byte IPv4 header with a chosen IP protocol
    /// number, wrapping `payload`. Mirrors the hand-rolled frame in the OSPF test.
    fn build_ipv4_proto(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        buf.extend_from_slice(&0x0800u16.to_be_bytes());
        let total_len = (20 + payload.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, proto, 0x00, 0x00]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn end_to_end_sctp_via_dissect() {
        let mut sctp = Vec::new();
        sctp.extend_from_slice(&1234u16.to_be_bytes());
        sctp.extend_from_slice(&38412u16.to_be_bytes());
        sctp.extend_from_slice(&[0u8; 8]); // vtag + checksum
        sctp.push(1); // INIT chunk
        let r = dissect(&build_ipv4_proto(132, &sctp));
        assert_eq!(r.protocol, Protocol::Sctp);
        assert!(r.summary.contains("INIT"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_igmp_via_dissect() {
        let mut igmp = vec![0x16, 0x00, 0x00, 0x00];
        igmp.extend_from_slice(&[239, 1, 2, 3]);
        let r = dissect(&build_ipv4_proto(2, &igmp));
        assert_eq!(r.protocol, Protocol::Igmp);
        assert!(r.summary.contains("239.1.2.3"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_gre_via_dissect() {
        let r = dissect(&build_ipv4_proto(47, &[0x00, 0x00, 0x08, 0x00]));
        assert_eq!(r.protocol, Protocol::Gre);
        assert!(r.summary.contains("IPv4"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_eapol_via_dissect() {
        // EtherType 0x888E, version 2, type 3 (Key / WPA handshake).
        let r = dissect(&build_eth_frame(0x888E, &[0x02, 0x03, 0x00, 0x5F]));
        assert_eq!(r.protocol, Protocol::Eapol);
        assert!(r.summary.contains("Key"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_pppoe_via_dissect() {
        // EtherType 0x8863 (discovery), code 0x09 (PADI).
        let r = dissect(&build_eth_frame(0x8863, &[0x11, 0x09, 0x00, 0x00]));
        assert_eq!(r.protocol, Protocol::Pppoe);
        assert!(r.summary.contains("PADI"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_vrrp_via_dissect() {
        let r = dissect(&build_ipv4_proto(112, &[0x31, 0x0A, 0x64, 0x00]));
        assert_eq!(r.protocol, Protocol::Vrrp);
        assert!(r.summary.contains("VRID 10"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_dccp_via_dissect() {
        let mut dccp = Vec::new();
        dccp.extend_from_slice(&5001u16.to_be_bytes());
        dccp.extend_from_slice(&5002u16.to_be_bytes());
        dccp.extend_from_slice(&[0u8; 4]); // offset, ccval, checksum
        dccp.push(0x00); // type 0 (Request)
        dccp.extend_from_slice(&[0u8; 3]);
        let r = dissect(&build_ipv4_proto(33, &dccp));
        assert_eq!(r.protocol, Protocol::Dccp);
        assert!(r.summary.contains("5001 → 5002"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_dtls_via_dissect() {
        // DTLS 1.2 Handshake record on an arbitrary UDP port — recognised
        // structurally, not by port.
        let mut dtls = vec![22, 0xFE, 0xFD, 0x00, 0x00];
        dtls.extend_from_slice(&[0u8; 8]);
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 50001, &dtls);
        let r = dissect(&pkt);
        assert_eq!(r.protocol, Protocol::Dtls);
        assert!(r.summary.contains("Handshake"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_profinet_via_dissect() {
        // EtherType 0x8892, FrameID 0xFEFC (DCP Identify).
        let r = dissect(&build_eth_frame(0x8892, &[0xFE, 0xFC, 0x05, 0x00]));
        assert_eq!(r.protocol, Protocol::Profinet);
        assert!(r.summary.contains("DCP Identify"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_wol_via_dissect() {
        // EtherType 0x0842 Wake-on-LAN magic packet.
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let mut magic = vec![0xFF; 6];
        for _ in 0..16 {
            magic.extend_from_slice(&mac);
        }
        let r = dissect(&build_eth_frame(0x0842, &magic));
        assert_eq!(r.protocol, Protocol::Wol);
    }

    #[test]
    fn end_to_end_fix_structural_via_dissect() {
        // FIX recognised by its "8=FIX" prefix on an arbitrary TCP port.
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            9999,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            b"8=FIX.4.4\x0135=D\x0149=A\x01",
        );
        let r = dissect(&data);
        assert_eq!(r.protocol, Protocol::Fix);
        assert!(r.summary.contains("NewOrderSingle"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_avtp_via_dissect() {
        let r = dissect(&build_eth_frame(0x22F0, &[0x22, 0x00, 0x00, 0x00]));
        assert_eq!(r.protocol, Protocol::Avtp);
    }

    #[test]
    fn end_to_end_dht_via_dissect() {
        let msg = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q9:get_peers1:y1:qe";
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 51000, msg);
        let r = dissect(&pkt);
        assert_eq!(r.protocol, Protocol::Dht);
    }

    #[test]
    fn end_to_end_source_query_via_dissect() {
        let mut q = vec![0xFF, 0xFF, 0xFF, 0xFF, b'T'];
        q.extend_from_slice(b"Source Engine Query\0");
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40000, 27015, &q);
        let r = dissect(&pkt);
        assert_eq!(r.protocol, Protocol::SourceQuery);
    }

    #[test]
    fn end_to_end_sampled_values_via_dissect() {
        let r = dissect(&build_eth_frame(0x88BA, &[0x40, 0x00, 0x00, 0x20]));
        assert_eq!(r.protocol, Protocol::Sv);
    }

    #[test]
    fn end_to_end_powerlink_via_dissect() {
        let r = dissect(&build_eth_frame(0x88AB, &[0x04, 0x01, 0xF0, 0x00]));
        assert_eq!(r.protocol, Protocol::Powerlink);
        assert!(r.summary.contains("PRes"), "{}", r.summary);
    }

    #[test]
    fn end_to_end_sercos_via_dissect() {
        let r = dissect(&build_eth_frame(0x88CD, &[0x00, 0x00, 0x00, 0x00]));
        assert_eq!(r.protocol, Protocol::Sercos);
    }

    #[test]
    fn end_to_end_rarp_via_dissect() {
        let r = dissect(&build_eth_frame(
            0x8035,
            &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03],
        ));
        assert_eq!(r.protocol, Protocol::Rarp);
        assert_eq!(r.summary, "RARP Request");
    }

    #[test]
    fn end_to_end_ethercat_via_dissect() {
        let r = dissect(&build_eth_frame(0x88A4, &[0x10, 0x10, 12, 0x00]));
        assert_eq!(r.protocol, Protocol::Ethercat);
    }

    #[test]
    fn end_to_end_macsec_via_dissect() {
        let r = dissect(&build_eth_frame(0x88E5, &[0x0D, 0x00, 0x00, 0x00]));
        assert_eq!(r.protocol, Protocol::Macsec);
    }

    #[test]
    fn end_to_end_rtps_via_dissect() {
        let mut rtps = b"RTPS".to_vec();
        rtps.extend_from_slice(&[0x02, 0x03]);
        rtps.extend_from_slice(&[0u8; 14]);
        rtps.push(0x15); // DATA submessage
        let pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 7400, 7401, &rtps);
        let r = dissect(&pkt);
        assert_eq!(r.protocol, Protocol::Rtps);
    }

    #[test]
    fn end_to_end_rsvp_via_dissect() {
        let r = dissect(&build_ipv4_proto(46, &[0x10, 0x01, 0x00, 0x00]));
        assert_eq!(r.protocol, Protocol::Rsvp);
        assert_eq!(r.summary, "RSVP Path");
    }

    #[test]
    fn end_to_end_goose_via_dissect() {
        let r = dissect(&build_eth_frame(0x88B8, &[0x00, 0x01, 0x00, 0x10]));
        assert_eq!(r.protocol, Protocol::Goose);
    }

    #[test]
    fn end_to_end_ptp_l2_via_dissect() {
        let r = dissect(&build_eth_frame(0x88F7, &[0x00, 0x02, 0x00, 0x2c]));
        assert_eq!(r.protocol, Protocol::Ptp);
        assert!(r.summary.contains("Sync"), "{}", r.summary);
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
                    TcpFlags {
                        ack: true,
                        ..Default::default()
                    },
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
                    TcpFlags {
                        syn: true,
                        ..Default::default()
                    },
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
