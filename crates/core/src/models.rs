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
    /// DCCP congestion-controlled datagram transport (IP protocol 33).
    Dccp,
    /// Datagram TLS — encryption over UDP (WebRTC/VPN media).
    Dtls,
    /// NetFlow / IPFIX flow export (UDP 2055/4739).
    Netflow,
    /// sFlow sampled-traffic export (UDP 6343).
    Sflow,
    /// Bidirectional Forwarding Detection (UDP 3784).
    Bfd,
    /// HSRP Cisco gateway redundancy (UDP 1985).
    Hsrp,
    /// iSCSI SCSI-over-TCP storage (TCP 3260).
    Iscsi,
    /// RTMP Flash/live streaming (TCP 1935).
    Rtmp,
    /// SMPP SMS gateway protocol (TCP 2775).
    Smpp,
    /// OpenFlow SDN switch control (TCP 6653).
    OpenFlow,
    /// NATS cloud messaging (TCP 4222).
    Nats,
    /// STOMP simple text messaging (TCP 61613).
    Stomp,
    /// PROFINET real-time industrial automation (EtherType 0x8892).
    Profinet,
    /// Wake-on-LAN magic packet (EtherType 0x0842 / UDP).
    Wol,
    /// GLBP Cisco gateway load balancing (UDP 3222).
    Glbp,
    /// WCCP web-cache redirection (UDP 2048).
    Wccp,
    /// MGCP VoIP media gateway control (UDP 2427/2727).
    Mgcp,
    /// NetBIOS Datagram Service (UDP 138).
    Nbds,
    /// DICOM medical imaging (TCP 104/11112).
    Dicom,
    /// HL7 v2 healthcare messaging (TCP 2575, MLLP).
    Hl7,
    /// FIX financial trading protocol (negotiated TCP ports).
    Fix,
    /// S7comm Siemens PLC protocol (TCP 102).
    S7comm,
    /// IEC 60870-5-104 SCADA telecontrol (TCP 2404).
    Iec104,
    /// LDP MPLS label distribution (TCP/UDP 646).
    Ldp,
    /// GOOSE IEC 61850 substation events (EtherType 0x88B8).
    Goose,
    /// PTP IEEE 1588 precision time sync (EtherType 0x88F7 / UDP 319/320).
    Ptp,
    /// RSVP QoS / MPLS-TE signalling (IP protocol 46).
    Rsvp,
    /// ISAKMP / IKE VPN key exchange (UDP 500/4500).
    Isakmp,
    /// Geneve network-virtualisation overlay (UDP 6081).
    Geneve,
    /// CAPWAP wireless AP control (UDP 5246/5247).
    Capwap,
    /// Teredo IPv6-over-UDP tunnelling (UDP 3544).
    Teredo,
    /// GVCP GigE Vision camera control (UDP 3956).
    Gvcp,
    /// ONC RPC — Portmap/NFS/Mount/NLM (TCP/UDP 111, 2049).
    Rpc,
    /// Graphite/Carbon plaintext metrics (TCP 2003).
    Graphite,
    /// Gearman job queue (TCP 4730).
    Gearman,
    /// beanstalkd work queue (TCP 11300).
    Beanstalk,
    /// EtherCAT real-time industrial fieldbus (EtherType 0x88A4).
    Ethercat,
    /// Fibre Channel over Ethernet storage (EtherType 0x8906).
    Fcoe,
    /// MACsec 802.1AE link-layer encryption (EtherType 0x88E5).
    Macsec,
    /// Reverse ARP (EtherType 0x8035).
    Rarp,
    /// RTPS / DDS real-time pub-sub middleware (dynamic UDP).
    Rtps,
    /// InfluxDB line-protocol metrics (UDP 8089).
    Influxdb,
    /// MQTT-SN sensor-network messaging (UDP 1883).
    MqttSn,
    /// Babel mesh routing protocol (UDP 6696).
    Babel,
    /// X11 display protocol (TCP 6000+).
    X11,
    /// rsync daemon file sync (TCP 873).
    Rsync,
    /// Subversion svnserve (TCP 3690).
    Svn,
    /// RethinkDB document database (TCP 28015).
    Rethinkdb,
    /// IEC 61850-9-2 Sampled Values (EtherType 0x88BA).
    Sv,
    /// Ethernet POWERLINK real-time industrial (EtherType 0x88AB).
    Powerlink,
    /// SERCOS III motion control (EtherType 0x88CD).
    Sercos,
    /// KNXnet/IP building automation (UDP 3671).
    Knxip,
    /// StatsD metrics (UDP 8125).
    Statsd,
    /// GELF Graylog structured logging (UDP 12201).
    Gelf,
    /// HART-IP industrial process instruments (UDP/TCP 5094).
    Hartip,
    /// Elasticsearch transport protocol (TCP 9300).
    Elasticsearch,
    /// Zabbix monitoring (TCP 10050/10051).
    Zabbix,
    /// NSQ realtime messaging (TCP 4150).
    Nsq,
    /// ZMTP / ZeroMQ messaging (dynamic TCP).
    Zmtp,
    /// Aerospike key-value database (TCP 3000).
    Aerospike,
    /// AVTP / IEEE 1722 audio-video transport (EtherType 0x22F0).
    Avtp,
    /// SOME/IP automotive service middleware (UDP/TCP 30490+).
    SomeIp,
    /// DoIP diagnostics over IP (UDP/TCP 13400).
    Doip,
    /// XCP ECU measurement/calibration (UDP/TCP 5555).
    Xcp,
    /// Matter smart-home protocol (UDP 5540).
    Matter,
    /// AFP Apple Filing Protocol (TCP 548).
    Afp,
    /// BitTorrent DHT / KRPC peer discovery (dynamic UDP).
    Dht,
    /// Gnutella peer-to-peer file sharing (TCP 6346).
    Gnutella,
    /// eDonkey/eMule peer-to-peer file sharing (TCP 4662).
    Edonkey,
    /// Source engine game-server query (A2S, UDP).
    SourceQuery,
    /// Minecraft Java Edition protocol (TCP 25565).
    Minecraft,
    /// Mumble voice-chat control (TCP 64738).
    Mumble,
    /// PFCP 4G/5G user-plane control, the N4 interface (UDP 8805).
    Pfcp,
    /// GTP' charging / CDR transfer (UDP 3386).
    GtpPrime,
    /// Megaco / H.248 media gateway control (UDP/TCP 2944).
    Megaco,
    /// MSRP instant messaging in SIP/IMS sessions (TCP 2855).
    Msrp,
    /// PCoIP remote display (UDP/TCP 4172).
    Pcoip,
    /// SPICE virtual-machine console (TCP, "REDQ" magic).
    Spice,
    /// Citrix ICA thin-client session (TCP 1494).
    Ica,
    /// NDMP network backup management (TCP 10000).
    Ndmp,
    /// DCE/RPC — Windows MSRPC (TCP 135 and dynamic ports).
    Dcerpc,
    /// PPTP VPN control channel (TCP 1723).
    Pptp,
    /// Radmin remote control (TCP 4899).
    Radmin,
    /// Skinny / SCCP Cisco IP-phone signalling (TCP 2000).
    Skinny,
    /// CLDAP — connectionless LDAP for AD discovery (UDP 389).
    Cldap,
    /// BMP — BGP Monitoring Protocol (TCP 11019).
    Bmp,
    /// RPKI-RTR — validated route origins for BGP security (TCP 323).
    RpkiRtr,
    /// MMS — IEC 61850 substation client/server messaging (TCP 102).
    Mms,
    /// NRPE — Nagios remote plugin executor (TCP 5666).
    Nrpe,
    /// collectd binary metric protocol (UDP 25826).
    Collectd,
    /// Jaeger distributed-tracing spans (UDP 6831).
    Jaeger,
    /// Ganglia gmond cluster metrics (UDP 8649).
    Ganglia,
    /// Neo4j Bolt graph-database protocol (TCP 7687).
    Bolt,
    /// ClickHouse native protocol (TCP 9000).
    Clickhouse,
    /// Apache Pulsar broker protocol (TCP 6650).
    Pulsar,
    /// OpenWire — Apache ActiveMQ native protocol (TCP 61616).
    Openwire,
    /// ZooKeeper coordination service (TCP 2181).
    Zookeeper,
    /// Hadoop RPC / HDFS NameNode (TCP 8020).
    HadoopRpc,
    /// Fluentd forward log collection (TCP 24224).
    Fluentd,
    /// Elastic Beats log shipping (TCP 5044).
    Beats,
    /// ClamAV antivirus daemon (TCP 3310).
    Clamav,
    /// SpamAssassin spamd (TCP 783).
    Spamd,
    /// ManageSieve mail-filter management (TCP 4190).
    ManageSieve,
    /// RELP reliable syslog transport (TCP 2514).
    Relp,
    /// LPD line printer daemon (TCP 515).
    Lpd,
    /// Ident user lookup (TCP 113).
    Ident,
    /// Gopher document protocol (TCP 70).
    Gopher,
    /// rsh BSD remote shell (TCP 514).
    Rsh,
    /// CDP — Cisco Discovery Protocol (LLC/SNAP).
    Cdp,
    /// VTP — Cisco VLAN Trunking Protocol (LLC/SNAP).
    Vtp,
    /// DTP — Cisco Dynamic Trunking Protocol (LLC/SNAP).
    Dtp,
    /// PAgP — Cisco Port Aggregation Protocol (LLC/SNAP).
    Pagp,
    /// UDLD — Cisco UniDirectional Link Detection (LLC/SNAP).
    Udld,
    /// EAP — the authentication method inside 802.1X / EAPOL.
    Eap,
    /// IPX — Novell NetWare network layer (EtherType 0x8137).
    Ipx,
    /// AppleTalk DDP (EtherType 0x809B).
    Atalk,
    /// AARP — AppleTalk address resolution (EtherType 0x80F3).
    Aarp,
    /// IPP — Internet Printing Protocol / CUPS (TCP 631).
    Ipp,
    /// rexec BSD remote execution, cleartext password (TCP 512).
    Rexec,
    /// SANE network scanner access (TCP 6566).
    Sane,
    /// Oracle TNS database transport (TCP 1521).
    Tns,
    /// DRDA — IBM Db2 database protocol (TCP 50000).
    Drda,
    /// Firebird / InterBase database protocol (TCP 3050).
    Firebird,
    /// MySQL X Protocol / document store (TCP 33060).
    MysqlX,
    /// Riak protocol-buffers client interface (TCP 8087).
    Riak,
    /// NMEA 0183 navigation sentences (TCP 10110).
    Nmea,
    /// ADS-B Beast aircraft telemetry (TCP 30005).
    Adsb,
    /// APRS-IS amateur-radio packet reporting (TCP 14580).
    Aprs,
    /// TURN relayed media (RFC 8656 ChannelData).
    Turn,
    /// DECnet Phase IV (EtherType 0x6003).
    Decnet,
    /// Banyan VINES (EtherType 0x0BAD).
    Vines,
    /// ERSPAN mirrored traffic tunnelled in GRE.
    Erspan,
    /// PPP inside a PPPoE session (LCP/IPCP/auth).
    Ppp,
    /// PAP — PPP authentication with a cleartext password.
    Pap,
    /// CHAP — PPP challenge-handshake authentication.
    Chap,
    /// L2CAP — the Bluetooth multiplexing layer.
    L2cap,
    /// ATT — the Bluetooth attribute protocol (BLE data).
    Att,
    /// SMP — Bluetooth LE pairing and bonding.
    Smp,
    /// NVMe over Fabrics on TCP (TCP 4420).
    NvmeOf,
    /// Network Block Device (TCP 10809).
    Nbd,
    /// FCIP — Fibre Channel over IP (TCP 3225).
    Fcip,
    /// ATA over Ethernet (EtherType 0x88A2).
    Aoe,
    /// RoCE — RDMA over Converged Ethernet (EtherType 0x8915).
    Roce,
    /// XDMCP — X Display Manager Control Protocol (UDP 177).
    Xdmcp,
    /// IAX2 — Asterisk inter-exchange VoIP trunking (UDP 4569).
    Iax2,
    /// ZRTP — in-band key agreement for encrypted voice.
    Zrtp,
    /// SQL Server Browser instance discovery (UDP 1434).
    MssqlBrowser,
    /// H.225 RAS — H.323 gatekeeper registration/admission (UDP 1719).
    H225Ras,
    /// H.225 / Q.931 call signalling (TCP 1720).
    Q931,
    /// BFCP — conference floor control (TCP 3238).
    Bfcp,
    /// LISP — Locator/ID Separation Protocol (UDP 4341/4342).
    Lisp,
    /// L2TPv3 pseudowire carried on IP (protocol 115).
    L2tpv3,
    /// VXLAN-GPE overlay with a next-protocol field (UDP 4790).
    VxlanGpe,
    /// PCP / NAT-PMP port mapping (UDP 5351).
    Pcp,
    /// rwho host broadcasts (UDP 513).
    Rwho,
    /// DHCP failover peer synchronisation (TCP 647).
    DhcpFailover,
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
            Protocol::Dccp => write!(f, "DCCP"),
            Protocol::Dtls => write!(f, "DTLS"),
            Protocol::Netflow => write!(f, "NetFlow"),
            Protocol::Sflow => write!(f, "sFlow"),
            Protocol::Bfd => write!(f, "BFD"),
            Protocol::Hsrp => write!(f, "HSRP"),
            Protocol::Iscsi => write!(f, "iSCSI"),
            Protocol::Rtmp => write!(f, "RTMP"),
            Protocol::Smpp => write!(f, "SMPP"),
            Protocol::OpenFlow => write!(f, "OpenFlow"),
            Protocol::Nats => write!(f, "NATS"),
            Protocol::Stomp => write!(f, "STOMP"),
            Protocol::Profinet => write!(f, "PROFINET"),
            Protocol::Wol => write!(f, "Wake-on-LAN"),
            Protocol::Glbp => write!(f, "GLBP"),
            Protocol::Wccp => write!(f, "WCCP"),
            Protocol::Mgcp => write!(f, "MGCP"),
            Protocol::Nbds => write!(f, "NetBIOS-DGM"),
            Protocol::Dicom => write!(f, "DICOM"),
            Protocol::Hl7 => write!(f, "HL7"),
            Protocol::Fix => write!(f, "FIX"),
            Protocol::S7comm => write!(f, "S7comm"),
            Protocol::Iec104 => write!(f, "IEC-104"),
            Protocol::Ldp => write!(f, "LDP"),
            Protocol::Goose => write!(f, "GOOSE"),
            Protocol::Ptp => write!(f, "PTP"),
            Protocol::Rsvp => write!(f, "RSVP"),
            Protocol::Isakmp => write!(f, "ISAKMP"),
            Protocol::Geneve => write!(f, "Geneve"),
            Protocol::Capwap => write!(f, "CAPWAP"),
            Protocol::Teredo => write!(f, "Teredo"),
            Protocol::Gvcp => write!(f, "GVCP"),
            Protocol::Rpc => write!(f, "RPC"),
            Protocol::Graphite => write!(f, "Graphite"),
            Protocol::Gearman => write!(f, "Gearman"),
            Protocol::Beanstalk => write!(f, "Beanstalk"),
            Protocol::Ethercat => write!(f, "EtherCAT"),
            Protocol::Fcoe => write!(f, "FCoE"),
            Protocol::Macsec => write!(f, "MACsec"),
            Protocol::Rarp => write!(f, "RARP"),
            Protocol::Rtps => write!(f, "RTPS/DDS"),
            Protocol::Influxdb => write!(f, "InfluxDB"),
            Protocol::MqttSn => write!(f, "MQTT-SN"),
            Protocol::Babel => write!(f, "Babel"),
            Protocol::X11 => write!(f, "X11"),
            Protocol::Rsync => write!(f, "rsync"),
            Protocol::Svn => write!(f, "SVN"),
            Protocol::Rethinkdb => write!(f, "RethinkDB"),
            Protocol::Sv => write!(f, "Sampled Values"),
            Protocol::Powerlink => write!(f, "POWERLINK"),
            Protocol::Sercos => write!(f, "SERCOS III"),
            Protocol::Knxip => write!(f, "KNXnet/IP"),
            Protocol::Statsd => write!(f, "StatsD"),
            Protocol::Gelf => write!(f, "GELF"),
            Protocol::Hartip => write!(f, "HART-IP"),
            Protocol::Elasticsearch => write!(f, "Elasticsearch"),
            Protocol::Zabbix => write!(f, "Zabbix"),
            Protocol::Nsq => write!(f, "NSQ"),
            Protocol::Zmtp => write!(f, "ZMTP"),
            Protocol::Aerospike => write!(f, "Aerospike"),
            Protocol::Avtp => write!(f, "AVTP"),
            Protocol::SomeIp => write!(f, "SOME/IP"),
            Protocol::Doip => write!(f, "DoIP"),
            Protocol::Xcp => write!(f, "XCP"),
            Protocol::Matter => write!(f, "Matter"),
            Protocol::Afp => write!(f, "AFP"),
            Protocol::Dht => write!(f, "BitTorrent DHT"),
            Protocol::Gnutella => write!(f, "Gnutella"),
            Protocol::Edonkey => write!(f, "eDonkey"),
            Protocol::SourceQuery => write!(f, "Source Query"),
            Protocol::Minecraft => write!(f, "Minecraft"),
            Protocol::Mumble => write!(f, "Mumble"),
            Protocol::Pfcp => write!(f, "PFCP"),
            Protocol::GtpPrime => write!(f, "GTP-prime"),
            Protocol::Megaco => write!(f, "Megaco"),
            Protocol::Msrp => write!(f, "MSRP"),
            Protocol::Pcoip => write!(f, "PCoIP"),
            Protocol::Spice => write!(f, "SPICE"),
            Protocol::Ica => write!(f, "ICA"),
            Protocol::Ndmp => write!(f, "NDMP"),
            Protocol::Dcerpc => write!(f, "DCERPC"),
            Protocol::Pptp => write!(f, "PPTP"),
            Protocol::Radmin => write!(f, "Radmin"),
            Protocol::Skinny => write!(f, "Skinny"),
            Protocol::Cldap => write!(f, "CLDAP"),
            Protocol::Bmp => write!(f, "BMP"),
            Protocol::RpkiRtr => write!(f, "RPKI-RTR"),
            Protocol::Mms => write!(f, "MMS"),
            Protocol::Nrpe => write!(f, "NRPE"),
            Protocol::Collectd => write!(f, "collectd"),
            Protocol::Jaeger => write!(f, "Jaeger"),
            Protocol::Ganglia => write!(f, "Ganglia"),
            Protocol::Bolt => write!(f, "Bolt"),
            Protocol::Clickhouse => write!(f, "ClickHouse"),
            Protocol::Pulsar => write!(f, "Pulsar"),
            Protocol::Openwire => write!(f, "OpenWire"),
            Protocol::Zookeeper => write!(f, "ZooKeeper"),
            Protocol::HadoopRpc => write!(f, "HadoopRPC"),
            Protocol::Fluentd => write!(f, "Fluentd"),
            Protocol::Beats => write!(f, "Beats"),
            Protocol::Clamav => write!(f, "ClamAV"),
            Protocol::Spamd => write!(f, "spamd"),
            Protocol::ManageSieve => write!(f, "ManageSieve"),
            Protocol::Relp => write!(f, "RELP"),
            Protocol::Lpd => write!(f, "LPD"),
            Protocol::Ident => write!(f, "Ident"),
            Protocol::Gopher => write!(f, "Gopher"),
            Protocol::Rsh => write!(f, "rsh"),
            Protocol::Cdp => write!(f, "CDP"),
            Protocol::Vtp => write!(f, "VTP"),
            Protocol::Dtp => write!(f, "DTP"),
            Protocol::Pagp => write!(f, "PAgP"),
            Protocol::Udld => write!(f, "UDLD"),
            Protocol::Eap => write!(f, "EAP"),
            Protocol::Ipx => write!(f, "IPX"),
            Protocol::Atalk => write!(f, "AppleTalk"),
            Protocol::Aarp => write!(f, "AARP"),
            Protocol::Ipp => write!(f, "IPP"),
            Protocol::Rexec => write!(f, "rexec"),
            Protocol::Sane => write!(f, "SANE"),
            Protocol::Tns => write!(f, "OracleTNS"),
            Protocol::Drda => write!(f, "DRDA"),
            Protocol::Firebird => write!(f, "Firebird"),
            Protocol::MysqlX => write!(f, "MySQLX"),
            Protocol::Riak => write!(f, "Riak"),
            Protocol::Nmea => write!(f, "NMEA"),
            Protocol::Adsb => write!(f, "ADSB"),
            Protocol::Aprs => write!(f, "APRS"),
            Protocol::Turn => write!(f, "TURN"),
            Protocol::Decnet => write!(f, "DECnet"),
            Protocol::Vines => write!(f, "VINES"),
            Protocol::Erspan => write!(f, "ERSPAN"),
            Protocol::Ppp => write!(f, "PPP"),
            Protocol::Pap => write!(f, "PAP"),
            Protocol::Chap => write!(f, "CHAP"),
            Protocol::L2cap => write!(f, "L2CAP"),
            Protocol::Att => write!(f, "ATT"),
            Protocol::Smp => write!(f, "SMP"),
            Protocol::NvmeOf => write!(f, "NVMeTCP"),
            Protocol::Nbd => write!(f, "NBD"),
            Protocol::Fcip => write!(f, "FCIP"),
            Protocol::Aoe => write!(f, "AoE"),
            Protocol::Roce => write!(f, "RoCE"),
            Protocol::Xdmcp => write!(f, "XDMCP"),
            Protocol::Iax2 => write!(f, "IAX2"),
            Protocol::Zrtp => write!(f, "ZRTP"),
            Protocol::MssqlBrowser => write!(f, "SQLBrowser"),
            Protocol::H225Ras => write!(f, "H225RAS"),
            Protocol::Q931 => write!(f, "Q931"),
            Protocol::Bfcp => write!(f, "BFCP"),
            Protocol::Lisp => write!(f, "LISP"),
            Protocol::L2tpv3 => write!(f, "L2TPv3"),
            Protocol::VxlanGpe => write!(f, "VXLANGPE"),
            Protocol::Pcp => write!(f, "PCP"),
            Protocol::Rwho => write!(f, "rwho"),
            Protocol::DhcpFailover => write!(f, "DHCPFailover"),
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
