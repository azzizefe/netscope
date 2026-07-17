// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Flow (conversation) tracking — groups packets into bidirectional
//! conversations keyed by endpoints + transport, like Wireshark's
//! "Conversations" window.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::models::{Packet, PluginTransport, Protocol};

/// Transport class used to group packets into flows. The application
/// protocol (HTTP, DNS, TLS...) may differ per packet, but the flow is
/// identified by its transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Other,
}

impl Transport {
    pub fn from_protocol(proto: &Protocol) -> Self {
        match proto {
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
            | Protocol::Ldap
            | Protocol::Mqtt
            | Protocol::Bgp
            | Protocol::Ntlm
            | Protocol::Smb
            | Protocol::Tds
            | Protocol::Amqp
            | Protocol::Kafka
            | Protocol::Rtsp
            | Protocol::Irc
            | Protocol::Rfb
            | Protocol::Whois
            | Protocol::Nntp
            | Protocol::Socks
            | Protocol::Memcached
            | Protocol::BitTorrent
            | Protocol::Git
            | Protocol::Xmpp
            | Protocol::Finger
            | Protocol::Tacacs
            | Protocol::Diameter
            | Protocol::Rlogin
            | Protocol::Iscsi
            | Protocol::Rtmp
            | Protocol::Smpp
            | Protocol::OpenFlow
            | Protocol::Nats
            | Protocol::Stomp
            | Protocol::Dicom
            | Protocol::Hl7
            | Protocol::Fix
            | Protocol::S7comm
            | Protocol::Iec104
            | Protocol::Ldp
            | Protocol::Rpc
            | Protocol::Graphite
            | Protocol::Gearman
            | Protocol::Beanstalk => Transport::Tcp,
            Protocol::Bacnet
            | Protocol::Kerberos
            | Protocol::Radius
            | Protocol::OpenVpn
            | Protocol::WireGuard
            | Protocol::Coap => Transport::Udp,
            // IPsec ESP/AH ride directly on IP; OSPF is IP protocol 89; and the
            // link-/operator-layer protocols aren't TCP/UDP at all.
            Protocol::Esp
            | Protocol::Ah
            | Protocol::Ospf
            | Protocol::Lldp
            | Protocol::Lacp
            | Protocol::Stp
            | Protocol::Mpls
            | Protocol::Sctp
            | Protocol::Gre
            | Protocol::Igmp
            | Protocol::Vrrp
            | Protocol::Pim
            | Protocol::Eigrp
            | Protocol::Pppoe
            | Protocol::Eapol
            | Protocol::Dccp
            | Protocol::Profinet
            | Protocol::Wol
            | Protocol::Goose
            | Protocol::Rsvp => Transport::Other,
            Protocol::Udp
            | Protocol::Dns
            | Protocol::Dhcp
            | Protocol::Ntp
            | Protocol::Mdns
            | Protocol::Snmp
            | Protocol::Quic
            | Protocol::Sip
            | Protocol::Vxlan
            | Protocol::Rtp
            | Protocol::Rtcp
            | Protocol::Syslog
            | Protocol::Tftp
            | Protocol::Ssdp
            | Protocol::Stun
            | Protocol::Llmnr
            | Protocol::Dhcpv6
            | Protocol::Rip
            | Protocol::Nbns
            | Protocol::L2tp
            | Protocol::Gtp
            | Protocol::Rmcp
            | Protocol::WsDiscovery
            | Protocol::Dtls
            | Protocol::Netflow
            | Protocol::Sflow
            | Protocol::Bfd
            | Protocol::Hsrp
            | Protocol::Glbp
            | Protocol::Wccp
            | Protocol::Mgcp
            | Protocol::Nbds
            | Protocol::Ptp
            | Protocol::Isakmp
            | Protocol::Geneve
            | Protocol::Capwap
            | Protocol::Teredo
            | Protocol::Gvcp => Transport::Udp,
            Protocol::Icmp => Transport::Icmp,
            Protocol::Arp => Transport::Arp,
            // A plugin-recognised protocol groups by the transport it declared,
            // so its packets share a flow with the plain TCP/UDP ones around it.
            Protocol::Plugin(p) => match p.transport {
                PluginTransport::Tcp => Transport::Tcp,
                PluginTransport::Udp => Transport::Udp,
            },
            // Hardware-bus captures (USB / Bluetooth HCI / CAN) have no
            // IP transport at all.
            Protocol::Wlan
            | Protocol::Usb
            | Protocol::Bluetooth
            | Protocol::Can
            | Protocol::Unknown(_) => Transport::Other,
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Tcp => write!(f, "TCP"),
            Transport::Udp => write!(f, "UDP"),
            Transport::Icmp => write!(f, "ICMP"),
            Transport::Arp => write!(f, "ARP"),
            Transport::Other => write!(f, "?"),
        }
    }
}

/// Bidirectional flow key: both directions of a conversation map to the
/// same key because the (addr, port) pairs are stored in sorted order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    endpoint_a: (IpAddr, Option<u16>),
    endpoint_b: (IpAddr, Option<u16>),
    transport: Transport,
}

impl FlowKey {
    fn from_packet(pkt: &Packet) -> Option<Self> {
        let src = (pkt.src_addr?, pkt.src_port);
        let dst = (pkt.dst_addr?, pkt.dst_port);
        let (endpoint_a, endpoint_b) = if src <= dst { (src, dst) } else { (dst, src) };
        Some(Self {
            endpoint_a,
            endpoint_b,
            transport: Transport::from_protocol(&pkt.protocol),
        })
    }
}

/// Aggregated statistics for one conversation.
#[derive(Debug, Clone)]
pub struct Flow {
    /// Address/port that sent the first packet of the flow (the initiator).
    pub client_addr: IpAddr,
    pub client_port: Option<u16>,
    /// Address/port that received the first packet.
    pub server_addr: IpAddr,
    pub server_port: Option<u16>,
    pub transport: Transport,
    /// Most specific application protocol observed (HTTP > TLS > DNS > transport).
    pub app_protocol: Protocol,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets_to_server: u64,
    pub packets_to_client: u64,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    /// Summary of the most recent packet, for at-a-glance context.
    pub last_summary: String,
}

impl Flow {
    pub fn duration(&self) -> chrono::Duration {
        self.end_time - self.start_time
    }
}

/// How specific a protocol is; higher wins when labeling a flow.
fn protocol_rank(proto: &Protocol) -> u8 {
    match proto {
        // WebSocket outranks HTTP: after the Upgrade handshake the whole
        // conversation is WebSocket, so that's the truer label for the flow.
        // Likewise gRPC outranks HTTP/2: the frames are HTTP/2 either way,
        // but a gRPC hit is the more specific truth about the conversation.
        Protocol::WebSocket | Protocol::Grpc => 5,
        Protocol::Http | Protocol::Http2 => 4,
        Protocol::Tls | Protocol::Quic => 3,
        Protocol::Dns
        | Protocol::Mdns
        | Protocol::Dhcp
        | Protocol::Ntp
        | Protocol::Snmp
        | Protocol::Sip
        | Protocol::Ssh
        | Protocol::Ftp
        | Protocol::Smtp
        | Protocol::Imap
        | Protocol::Pop3
        | Protocol::Telnet
        | Protocol::Rdp
        | Protocol::Vxlan
        | Protocol::Postgres
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Redis
        | Protocol::Cassandra
        | Protocol::Modbus
        | Protocol::Dnp3
        | Protocol::Bacnet
        | Protocol::Enip
        | Protocol::OpcUa
        | Protocol::Rtp
        | Protocol::Rtcp
        | Protocol::Kerberos
        | Protocol::Ldap
        | Protocol::Radius
        | Protocol::OpenVpn
        | Protocol::WireGuard
        | Protocol::Esp
        | Protocol::Ah
        | Protocol::Mqtt
        | Protocol::Coap
        | Protocol::Bgp
        | Protocol::Ospf
        | Protocol::Lldp
        | Protocol::Lacp
        | Protocol::Stp
        | Protocol::Mpls
        | Protocol::Ntlm
        | Protocol::Smb
        | Protocol::Tds
        | Protocol::Amqp
        | Protocol::Kafka
        | Protocol::Syslog
        | Protocol::Tftp
        | Protocol::Ssdp
        | Protocol::Stun
        | Protocol::Llmnr
        | Protocol::Rtsp
        | Protocol::Irc
        | Protocol::Rfb
        | Protocol::Whois
        | Protocol::Nntp
        | Protocol::Sctp
        | Protocol::Gre
        | Protocol::Igmp
        | Protocol::Dhcpv6
        | Protocol::Rip
        | Protocol::Nbns
        | Protocol::Socks
        | Protocol::Memcached
        | Protocol::BitTorrent
        | Protocol::Git
        | Protocol::Xmpp
        | Protocol::Finger
        | Protocol::Vrrp
        | Protocol::Pim
        | Protocol::Eigrp
        | Protocol::Pppoe
        | Protocol::Eapol
        | Protocol::L2tp
        | Protocol::Gtp
        | Protocol::Rmcp
        | Protocol::WsDiscovery
        | Protocol::Tacacs
        | Protocol::Diameter
        | Protocol::Rlogin
        | Protocol::Dccp
        | Protocol::Dtls
        | Protocol::Netflow
        | Protocol::Sflow
        | Protocol::Bfd
        | Protocol::Hsrp
        | Protocol::Iscsi
        | Protocol::Rtmp
        | Protocol::Smpp
        | Protocol::OpenFlow
        | Protocol::Nats
        | Protocol::Stomp
        | Protocol::Profinet
        | Protocol::Wol
        | Protocol::Glbp
        | Protocol::Wccp
        | Protocol::Mgcp
        | Protocol::Nbds
        | Protocol::Dicom
        | Protocol::Hl7
        | Protocol::Fix
        | Protocol::S7comm
        | Protocol::Iec104
        | Protocol::Ldp
        | Protocol::Goose
        | Protocol::Ptp
        | Protocol::Rsvp
        | Protocol::Isakmp
        | Protocol::Geneve
        | Protocol::Capwap
        | Protocol::Teredo
        | Protocol::Gvcp
        | Protocol::Rpc
        | Protocol::Graphite
        | Protocol::Gearman
        | Protocol::Beanstalk => 3,
        // A plugin naming the traffic is more specific than bare TCP/UDP, so
        // it wins the flow label — but yields to a built-in app protocol.
        Protocol::Plugin(_) => 4,
        Protocol::Tcp
        | Protocol::Udp
        | Protocol::Icmp
        | Protocol::Arp
        | Protocol::Wlan
        | Protocol::Usb
        | Protocol::Bluetooth
        | Protocol::Can => 1,
        Protocol::Unknown(_) => 0,
    }
}

/// Groups packets into flows. Feed it every packet via [`FlowTable::record`],
/// read the aggregated conversations back with [`FlowTable::flows`].
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    order: Vec<FlowKey>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, pkt: &Packet) {
        let Some(key) = FlowKey::from_packet(pkt) else {
            return;
        };

        match self.flows.get_mut(&key) {
            Some(flow) => {
                flow.packet_count += 1;
                flow.byte_count += pkt.length as u64;
                if pkt.src_addr == Some(flow.client_addr) && pkt.src_port == flow.client_port {
                    flow.packets_to_server += 1;
                } else {
                    flow.packets_to_client += 1;
                }
                if pkt.timestamp > flow.end_time {
                    flow.end_time = pkt.timestamp;
                }
                if pkt.timestamp < flow.start_time {
                    flow.start_time = pkt.timestamp;
                }
                if protocol_rank(&pkt.protocol) > protocol_rank(&flow.app_protocol) {
                    flow.app_protocol = pkt.protocol.clone();
                }
                flow.last_summary = pkt.summary.clone();
            }
            None => {
                let flow = Flow {
                    client_addr: pkt.src_addr.expect("checked by FlowKey::from_packet"),
                    client_port: pkt.src_port,
                    server_addr: pkt.dst_addr.expect("checked by FlowKey::from_packet"),
                    server_port: pkt.dst_port,
                    transport: key.transport,
                    app_protocol: pkt.protocol.clone(),
                    packet_count: 1,
                    byte_count: pkt.length as u64,
                    packets_to_server: 1,
                    packets_to_client: 0,
                    start_time: pkt.timestamp,
                    end_time: pkt.timestamp,
                    last_summary: pkt.summary.clone(),
                };
                self.flows.insert(key.clone(), flow);
                self.order.push(key);
            }
        }
    }

    /// Flows in first-seen order.
    pub fn flows(&self) -> Vec<&Flow> {
        self.order
            .iter()
            .filter_map(|k| self.flows.get(k))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
        proto: Protocol,
        len: usize,
        ts: &str,
    ) -> Packet {
        Packet {
            timestamp: ts.parse().unwrap(),
            src_addr: Some(src.parse().unwrap()),
            dst_addr: Some(dst.parse().unwrap()),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: proto,
            length: len,
            summary: format!("{src}:{src_port} → {dst}:{dst_port}"),
            data: bytes::Bytes::new(),
        }
    }

    #[test]
    fn both_directions_map_to_one_flow() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.record(&packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            Protocol::Tcp,
            120,
            "2024-01-01T00:00:01Z",
        ));

        assert_eq!(table.len(), 1);
        let flows = table.flows();
        let flow = flows[0];
        assert_eq!(flow.packet_count, 2);
        assert_eq!(flow.byte_count, 180);
        assert_eq!(flow.packets_to_server, 1);
        assert_eq!(flow.packets_to_client, 1);
        // Initiator is the first packet's source.
        assert_eq!(flow.client_addr.to_string(), "10.0.0.1");
        assert_eq!(flow.client_port, Some(12345));
        assert_eq!(flow.server_port, Some(80));
        assert_eq!(flow.duration().num_seconds(), 1);
    }

    #[test]
    fn different_ports_are_different_flows() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            1111,
            80,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            2222,
            80,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn tcp_and_udp_between_same_endpoints_are_separate() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            5000,
            53,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            5000,
            53,
            Protocol::Dns,
            60,
            "2024-01-01T00:00:00Z",
        ));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn app_protocol_upgrades_from_tcp_to_http() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            Protocol::Http,
            200,
            "2024-01-01T00:00:01Z",
        ));
        table.record(&packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:02Z",
        ));

        let flows = table.flows();
        assert_eq!(flows.len(), 1);
        // Label sticks to the most specific protocol seen.
        assert_eq!(flows[0].app_protocol, Protocol::Http);
        assert_eq!(flows[0].transport, Transport::Tcp);
    }

    #[test]
    fn packets_without_addresses_are_skipped() {
        let mut table = FlowTable::new();
        let mut pkt = packet(
            "10.0.0.1",
            "10.0.0.2",
            1,
            2,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        );
        pkt.src_addr = None;
        table.record(&pkt);
        assert!(table.is_empty());
    }

    #[test]
    fn flows_keep_first_seen_order() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            1111,
            80,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.record(&packet(
            "10.0.0.3",
            "10.0.0.4",
            2222,
            443,
            Protocol::Tls,
            60,
            "2024-01-01T00:00:01Z",
        ));
        let flows = table.flows();
        assert_eq!(flows[0].client_port, Some(1111));
        assert_eq!(flows[1].client_port, Some(2222));
    }

    #[test]
    fn clear_resets_table() {
        let mut table = FlowTable::new();
        table.record(&packet(
            "10.0.0.1",
            "10.0.0.2",
            1,
            2,
            Protocol::Tcp,
            60,
            "2024-01-01T00:00:00Z",
        ));
        table.clear();
        assert!(table.is_empty());
        assert!(table.flows().is_empty());
    }
}
