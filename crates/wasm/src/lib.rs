use wasm_bindgen::prelude::*;
use netscope_core::filter::Filter;
use netscope_core::models::{Packet, Protocol};
use bytes::Bytes;
use std::net::IpAddr;
use chrono::{Utc, TimeZone};
use serde::Deserialize;

#[wasm_bindgen]
pub struct WasmFilter {
    filter: Filter,
}

#[derive(Deserialize, Default)]
pub struct JsPacket {
    #[serde(default)]
    pub epoch_ms: i64,
    #[serde(default)]
    pub src_addr: Option<String>,
    #[serde(default)]
    pub dst_addr: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub length: usize,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub raw: Vec<u8>,
}

#[wasm_bindgen]
impl WasmFilter {
    #[wasm_bindgen]
    pub fn compile(text: &str) -> Result<WasmFilter, String> {
        let filter = Filter::parse(text).map_err(|e| e.to_string())?;
        Ok(WasmFilter { filter })
    }

    #[wasm_bindgen]
    pub fn matches(&self, pkt: JsValue) -> bool {
        let js_pkt: JsPacket = match serde_wasm_bindgen::from_value(pkt) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pkt = js_pkt.to_packet();
        self.filter.matches(&pkt)
    }
}

#[wasm_bindgen]
pub fn matches_batch(filter: &WasmFilter, packets: JsValue) -> Result<Vec<u8>, String> {
    let js_pkts: Vec<JsPacket> = serde_wasm_bindgen::from_value(packets)
        .map_err(|e| format!("failed to deserialize packets: {}", e))?;
    let results = js_pkts.into_iter()
        .map(|jp| if filter.filter.matches(&jp.to_packet()) { 1 } else { 0 })
        .collect();
    Ok(results)
}

fn parse_protocol(s: &str) -> Protocol {
    match s.to_uppercase().as_str() {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        "DNS" => Protocol::Dns,
        "HTTP" => Protocol::Http,
        "TLS" => Protocol::Tls,
        "ICMP" => Protocol::Icmp,
        "ARP" => Protocol::Arp,
        "DHCP" => Protocol::Dhcp,
        "NTP" => Protocol::Ntp,
        "MDNS" => Protocol::Mdns,
        "SNMP" => Protocol::Snmp,
        "QUIC" => Protocol::Quic,
        "SIP" => Protocol::Sip,
        "SSH" => Protocol::Ssh,
        "FTP" => Protocol::Ftp,
        "SMTP" => Protocol::Smtp,
        "IMAP" => Protocol::Imap,
        "POP3" => Protocol::Pop3,
        "TELNET" => Protocol::Telnet,
        "RDP" => Protocol::Rdp,
        "WEBSOCKET" => Protocol::WebSocket,
        "HTTP/2" => Protocol::Http2,
        "GRPC" => Protocol::Grpc,
        "VXLAN" => Protocol::Vxlan,
        "POSTGRESQL" => Protocol::Postgres,
        "MYSQL" => Protocol::Mysql,
        "MONGODB" => Protocol::Mongodb,
        "REDIS" => Protocol::Redis,
        "CASSANDRA" => Protocol::Cassandra,
        "MODBUS" => Protocol::Modbus,
        "DNP3" => Protocol::Dnp3,
        "BACNET" => Protocol::Bacnet,
        "ETHERNET/IP" => Protocol::Enip,
        "OPC UA" => Protocol::OpcUa,
        "RTP" => Protocol::Rtp,
        "RTCP" => Protocol::Rtcp,
        "KERBEROS" => Protocol::Kerberos,
        "LDAP" => Protocol::Ldap,
        "RADIUS" => Protocol::Radius,
        "OPENVPN" => Protocol::OpenVpn,
        "WIREGUARD" => Protocol::WireGuard,
        "ESP" => Protocol::Esp,
        "AH" => Protocol::Ah,
        "MQTT" => Protocol::Mqtt,
        "COAP" => Protocol::Coap,
        "BGP" => Protocol::Bgp,
        "OSPF" => Protocol::Ospf,
        "LLDP" => Protocol::Lldp,
        "LACP" => Protocol::Lacp,
        "STP" => Protocol::Stp,
        "MPLS" => Protocol::Mpls,
        "802.11" | "WLAN" | "WIFI" => Protocol::Wlan,
        "USB" => Protocol::Usb,
        "BT HCI" | "BLUETOOTH" => Protocol::Bluetooth,
        "CAN" => Protocol::Can,
        "NTLM" => Protocol::Ntlm,
        "SMB" => Protocol::Smb,
        "TDS" => Protocol::Tds,
        "AMQP" => Protocol::Amqp,
        "KAFKA" => Protocol::Kafka,
        other => Protocol::Plugin(netscope_core::models::PluginProto {
            name: other.to_string(),
            transport: netscope_core::models::PluginTransport::Tcp,
        }),
    }
}

impl JsPacket {
    fn to_packet(self) -> Packet {
        let timestamp = Utc.timestamp_millis_opt(self.epoch_ms).unwrap();
        let src_addr = self.src_addr.and_then(|s| s.parse::<IpAddr>().ok());
        let dst_addr = self.dst_addr.and_then(|s| s.parse::<IpAddr>().ok());
        let protocol = parse_protocol(&self.protocol);
        Packet {
            timestamp,
            src_addr,
            dst_addr,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol,
            length: self.length,
            summary: self.summary,
            data: Bytes::from(self.raw),
        }
    }
}
