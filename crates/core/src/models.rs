// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use bytes::Bytes;
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
    /// DHCP / BOOTP address assignment (UDP 67/68).
    Dhcp,
    /// Network Time Protocol (UDP 123).
    Ntp,
    /// Multicast DNS service discovery (UDP 5353).
    Mdns,
    /// Simple Network Management Protocol (UDP 161/162).
    Snmp,
    /// QUIC transport / HTTP-3 (UDP, usually 443).
    Quic,
    /// Session Initiation Protocol for VoIP signalling (UDP/TCP 5060/5061).
    Sip,
    /// Secure Shell (TCP 22).
    Ssh,
    /// File Transfer Protocol control channel (TCP 21).
    Ftp,
    /// Simple Mail Transfer Protocol (TCP 25/587).
    Smtp,
    /// Internet Message Access Protocol (TCP 143).
    Imap,
    /// Post Office Protocol v3 (TCP 110).
    Pop3,
    /// Telnet remote terminal (TCP 23).
    Telnet,
    /// Remote Desktop Protocol (TCP 3389).
    Rdp,
    /// WebSocket data frames (RFC 6455) — any TCP port, after an HTTP Upgrade.
    WebSocket,
    /// HTTP/2 cleartext frames (RFC 9113, h2c) — any TCP port.
    Http2,
    /// gRPC calls riding on HTTP/2 — usually TCP 50051, but any port.
    Grpc,
    /// VXLAN overlay encapsulation (RFC 7348, UDP 4789) — carries an inner Ethernet frame.
    Vxlan,
    /// PostgreSQL frontend/backend protocol (TCP 5432).
    Postgres,
    /// MySQL / MariaDB client-server protocol (TCP 3306).
    Mysql,
    /// MongoDB wire protocol (TCP 27017).
    Mongodb,
    /// Redis serialization protocol, RESP (TCP 6379).
    Redis,
    /// Cassandra CQL native binary protocol (TCP 9042).
    Cassandra,
    /// Modbus/TCP industrial control protocol (TCP 502).
    Modbus,
    /// DNP3 SCADA protocol for utilities (TCP/UDP 20000).
    Dnp3,
    /// BACnet/IP building automation (UDP 47808).
    Bacnet,
    /// EtherNet/IP + CIP industrial protocol (TCP/UDP 44818).
    Enip,
    /// OPC UA binary industrial protocol (TCP 4840).
    OpcUa,
    /// Real-time Transport Protocol media stream (RFC 3550) — dynamic UDP ports.
    Rtp,
    /// RTP Control Protocol — sender/receiver reports alongside an RTP stream.
    Rtcp,
    /// Kerberos authentication (TCP/UDP 88).
    Kerberos,
    /// Lightweight Directory Access Protocol (TCP 389).
    Ldap,
    /// RADIUS network access authentication (UDP 1812/1813).
    Radius,
    /// OpenVPN tunnel (UDP/TCP 1194).
    OpenVpn,
    /// WireGuard tunnel (UDP 51820).
    WireGuard,
    /// IPsec Encapsulating Security Payload (IP protocol 50).
    Esp,
    /// IPsec Authentication Header (IP protocol 51).
    Ah,
    /// MQTT IoT messaging protocol (TCP 1883).
    Mqtt,
    /// CoAP constrained-device protocol (UDP 5683).
    Coap,
    /// Border Gateway Protocol — internet inter-domain routing (TCP 179).
    Bgp,
    /// Open Shortest Path First — interior routing (IP protocol 89).
    Ospf,
    /// Link Layer Discovery Protocol — neighbour/topology (EtherType 0x88CC).
    Lldp,
    /// Link Aggregation Control Protocol / 802.3 slow protocols (EtherType 0x8809).
    Lacp,
    /// Spanning Tree Protocol BPDU — L2 loop prevention (802.3 LLC).
    Stp,
    /// MPLS label-switched packet (EtherType 0x8847/0x8848).
    Mpls,
    /// IEEE 802.11 (Wi-Fi) link-layer frame — management/control/data.
    Wlan,
    /// USB traffic captured on the bus (usbmon on Linux, USBPcap on Windows).
    Usb,
    /// Bluetooth HCI packet (command/event/ACL/SCO between host and controller).
    Bluetooth,
    /// CAN bus frame (SocketCAN capture — vehicle/industrial buses).
    Can,
    /// NT LAN Manager Security Support Provider (NTLMSSP).
    Ntlm,
    Smb,
    Tds,
    Amqp,
    Kafka,
    /// Syslog event logging (UDP 514).
    Syslog,
    /// Trivial File Transfer Protocol (UDP 69).
    Tftp,
    /// SSDP / UPnP device discovery (UDP 1900).
    Ssdp,
    /// STUN NAT-traversal for WebRTC/VoIP (UDP 3478).
    Stun,
    /// Link-Local Multicast Name Resolution (UDP 5355) — DNS wire format.
    Llmnr,
    /// Real Time Streaming Protocol media control (TCP 554).
    Rtsp,
    /// Internet Relay Chat (TCP 6667).
    Irc,
    /// Remote Framebuffer / VNC remote desktop (TCP 5900).
    Rfb,
    /// WHOIS registration lookups (TCP 43).
    Whois,
    /// Network News Transfer Protocol / Usenet (TCP 119).
    Nntp,
    /// SCTP transport with multi-streaming (IP protocol 132).
    Sctp,
    /// Generic Routing Encapsulation tunnel (IP protocol 47).
    Gre,
    /// IGMP IPv4 multicast group management (IP protocol 2).
    Igmp,
    /// DHCPv6 address assignment (UDP 546/547).
    Dhcpv6,
    /// Routing Information Protocol (UDP 520).
    Rip,
    /// NetBIOS Name Service (UDP 137).
    Nbns,
    /// SOCKS proxy (TCP 1080).
    Socks,
    /// Memcached key-value cache (TCP 11211).
    Memcached,
    /// BitTorrent peer-to-peer file sharing (TCP 6881-6889).
    BitTorrent,
    /// Git native transport (TCP 9418).
    Git,
    /// XMPP / Jabber instant messaging (TCP 5222).
    Xmpp,
    /// Finger user lookup (TCP 79).
    Finger,
    /// VRRP gateway redundancy (IP protocol 112).
    Vrrp,
    /// PIM multicast routing (IP protocol 103).
    Pim,
    /// EIGRP interior routing (IP protocol 88).
    Eigrp,
    /// PPPoE — PPP over Ethernet (EtherType 0x8863/0x8864).
    Pppoe,
    /// EAPOL / 802.1X port authentication (EtherType 0x888E).
    Eapol,
    /// L2TP tunnelling (UDP 1701).
    L2tp,
    /// GTP GPRS tunnelling for mobile networks (UDP 2123/2152).
    Gtp,
    /// RMCP / IPMI out-of-band server management (UDP 623).
    Rmcp,
    /// WS-Discovery device discovery (UDP 3702).
    WsDiscovery,
    /// TACACS+ device administration AAA (TCP 49).
    Tacacs,
    /// Diameter AAA protocol (TCP/SCTP 3868).
    Diameter,
    /// rlogin legacy remote login (TCP 513).
    Rlogin,
    /// A protocol recognised by a user-defined plugin (see [`crate::plugins`]).
    /// Carries the plugin's display name and the transport it rode on, so the
    /// protocol column shows the name and flows still group by transport.
    Plugin(PluginProto),
    Unknown(String),
}

/// The transport a plugin-recognised protocol runs over. Kept minimal (and
/// local to `models`) because `flows::Transport` can't be referenced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginTransport {
    Tcp,
    Udp,
}

/// Identity of a plugin-recognised protocol: the display name shown in the
/// protocol column plus the transport it rides on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginProto {
    pub name: String,
    pub transport: PluginTransport,
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
            Protocol::Dhcp => write!(f, "DHCP"),
            Protocol::Ntp => write!(f, "NTP"),
            Protocol::Mdns => write!(f, "mDNS"),
            Protocol::Snmp => write!(f, "SNMP"),
            Protocol::Quic => write!(f, "QUIC"),
            Protocol::Sip => write!(f, "SIP"),
            Protocol::Ssh => write!(f, "SSH"),
            Protocol::Ftp => write!(f, "FTP"),
            Protocol::Smtp => write!(f, "SMTP"),
            Protocol::Imap => write!(f, "IMAP"),
            Protocol::Pop3 => write!(f, "POP3"),
            Protocol::Telnet => write!(f, "Telnet"),
            Protocol::Rdp => write!(f, "RDP"),
            Protocol::WebSocket => write!(f, "WebSocket"),
            Protocol::Http2 => write!(f, "HTTP/2"),
            Protocol::Grpc => write!(f, "gRPC"),
            Protocol::Vxlan => write!(f, "VXLAN"),
            Protocol::Postgres => write!(f, "PostgreSQL"),
            Protocol::Mysql => write!(f, "MySQL"),
            Protocol::Mongodb => write!(f, "MongoDB"),
            Protocol::Redis => write!(f, "Redis"),
            Protocol::Cassandra => write!(f, "Cassandra"),
            Protocol::Modbus => write!(f, "Modbus"),
            Protocol::Dnp3 => write!(f, "DNP3"),
            Protocol::Bacnet => write!(f, "BACnet"),
            Protocol::Enip => write!(f, "EtherNet/IP"),
            Protocol::OpcUa => write!(f, "OPC UA"),
            Protocol::Rtp => write!(f, "RTP"),
            Protocol::Rtcp => write!(f, "RTCP"),
            Protocol::Kerberos => write!(f, "Kerberos"),
            Protocol::Ldap => write!(f, "LDAP"),
            Protocol::Radius => write!(f, "RADIUS"),
            Protocol::OpenVpn => write!(f, "OpenVPN"),
            Protocol::WireGuard => write!(f, "WireGuard"),
            Protocol::Esp => write!(f, "ESP"),
            Protocol::Ah => write!(f, "AH"),
            Protocol::Mqtt => write!(f, "MQTT"),
            Protocol::Coap => write!(f, "CoAP"),
            Protocol::Bgp => write!(f, "BGP"),
            Protocol::Ospf => write!(f, "OSPF"),
            Protocol::Lldp => write!(f, "LLDP"),
            Protocol::Lacp => write!(f, "LACP"),
            Protocol::Stp => write!(f, "STP"),
            Protocol::Mpls => write!(f, "MPLS"),
            Protocol::Wlan => write!(f, "802.11"),
            Protocol::Usb => write!(f, "USB"),
            Protocol::Bluetooth => write!(f, "BT HCI"),
            Protocol::Can => write!(f, "CAN"),
            Protocol::Ntlm => write!(f, "NTLM"),
            Protocol::Smb => write!(f, "SMB"),
            Protocol::Tds => write!(f, "TDS"),
            Protocol::Amqp => write!(f, "AMQP"),
            Protocol::Kafka => write!(f, "Kafka"),
            Protocol::Syslog => write!(f, "Syslog"),
            Protocol::Tftp => write!(f, "TFTP"),
            Protocol::Ssdp => write!(f, "SSDP"),
            Protocol::Stun => write!(f, "STUN"),
            Protocol::Llmnr => write!(f, "LLMNR"),
            Protocol::Rtsp => write!(f, "RTSP"),
            Protocol::Irc => write!(f, "IRC"),
            Protocol::Rfb => write!(f, "VNC/RFB"),
            Protocol::Whois => write!(f, "WHOIS"),
            Protocol::Nntp => write!(f, "NNTP"),
            Protocol::Sctp => write!(f, "SCTP"),
            Protocol::Gre => write!(f, "GRE"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Dhcpv6 => write!(f, "DHCPv6"),
            Protocol::Rip => write!(f, "RIP"),
            Protocol::Nbns => write!(f, "NBNS"),
            Protocol::Socks => write!(f, "SOCKS"),
            Protocol::Memcached => write!(f, "Memcached"),
            Protocol::BitTorrent => write!(f, "BitTorrent"),
            Protocol::Git => write!(f, "Git"),
            Protocol::Xmpp => write!(f, "XMPP"),
            Protocol::Finger => write!(f, "Finger"),
            Protocol::Vrrp => write!(f, "VRRP"),
            Protocol::Pim => write!(f, "PIM"),
            Protocol::Eigrp => write!(f, "EIGRP"),
            Protocol::Pppoe => write!(f, "PPPoE"),
            Protocol::Eapol => write!(f, "EAPOL"),
            Protocol::L2tp => write!(f, "L2TP"),
            Protocol::Gtp => write!(f, "GTP"),
            Protocol::Rmcp => write!(f, "RMCP"),
            Protocol::WsDiscovery => write!(f, "WS-Discovery"),
            Protocol::Tacacs => write!(f, "TACACS+"),
            Protocol::Diameter => write!(f, "Diameter"),
            Protocol::Rlogin => write!(f, "rlogin"),
            Protocol::Plugin(p) => write!(f, "{}", p.name),
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
    /// Raw frame bytes. [`Bytes`] instead of `Vec<u8>` so cloning a packet —
    /// flows, the stream LRU cache, UI copies — shares one refcounted buffer
    /// instead of reallocating the payload (ROADMAP §4.2).
    pub data: Bytes,
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
            data: vec![0u8; 100].into(),
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
            data: bytes::Bytes::new(),
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
