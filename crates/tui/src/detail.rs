//! Wireshark-style layered protocol tree for the TUI packet detail pane
//! (ROADMAP §6.1). Given a [`Packet`], [`build_tree`] walks the raw frame
//! bytes — Ethernet (+ VLAN tags) → IPv4/IPv6 → TCP/UDP — and returns the
//! protocol stack as collapsible [`DetailNode`]s, one per layer, each with a
//! handful of decoded fields. This mirrors the desktop `buildDetailTree`
//! (app.js) so the two UIs describe a packet the same way.

use netscope_core::education::explain_packet;
use netscope_core::models::{Packet, Protocol};

/// One layer in the detail tree: a heading plus its decoded fields. Rendered
/// as a collapsible node — the heading is always shown, the fields hide when
/// the node is collapsed.
pub struct DetailNode {
    /// Layer name, e.g. "Ethernet II", "Internet Protocol (IPv4)".
    pub title: String,
    /// Short context shown dimmed after the title, e.g. "54 bytes on wire".
    pub subtitle: String,
    /// `(name, value)` field rows.
    pub fields: Vec<(String, String)>,
}

impl DetailNode {
    fn new(title: impl Into<String>, subtitle: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: subtitle.into(),
            fields: Vec::new(),
        }
    }

    fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
}

const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88a8, 0x9100];

fn u16be(raw: &[u8], off: usize) -> u16 {
    ((raw[off] as u16) << 8) | raw[off + 1] as u16
}

fn mac_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Which transport layer sits under an application protocol, for the layer
/// chain shown in the Frame node. Mirrors `transportName` in app.js.
fn transport_name(proto: &Protocol) -> Option<&'static str> {
    use Protocol::*;
    match proto {
        Tcp | Http | Tls | WebSocket | Http2 | Grpc | Postgres | Mysql | Mongodb | Redis
        | Cassandra | Modbus | Dnp3 | Enip | OpcUa | Ldap | Mqtt | Bgp | Ssh | Ftp | Smtp
        | Imap | Pop3 | Telnet | Rdp => Some("TCP"),
        Udp | Dns | Mdns | Dhcp | Ntp | Snmp | Quic | Sip | Bacnet | Rtp | Rtcp | Kerberos
        | Radius | OpenVpn | WireGuard | Coap | Vxlan => Some("UDP"),
        _ => None,
    }
}

/// Build the layered protocol tree for `pkt`. Always returns at least the
/// Frame and Application nodes; link/network/transport nodes appear when the
/// captured bytes reach that layer.
pub fn build_tree(pkt: &Packet, index: usize) -> Vec<DetailNode> {
    let raw = &pkt.data;
    let mut nodes = Vec::new();

    let ip_ver = pkt
        .src_addr
        .map(|a| if a.is_ipv6() { "IPv6" } else { "IPv4" });
    let transport = transport_name(&pkt.protocol);
    let proto_name = pkt.protocol.to_string();

    // Layer chain, e.g. "Ethernet · IPv4 · TCP · HTTP".
    let mut chain: Vec<String> = vec!["Ethernet".to_string()];
    if let Some(v) = ip_ver {
        chain.push(v.to_string());
    }
    if let Some(t) = transport {
        if t != proto_name {
            chain.push(t.to_string());
        }
    }
    if !chain.contains(&proto_name) {
        chain.push(proto_name.clone());
    }

    nodes.push(
        DetailNode::new(
            format!("Frame {}", index + 1),
            format!("{} bytes on wire", pkt.length),
        )
        .field(
            "Arrival time",
            pkt.timestamp.format("%H:%M:%S%.3f").to_string(),
        )
        .field("Frame length", format!("{} bytes", pkt.length))
        .field("Captured bytes", format!("{} bytes", raw.len()))
        .field("Protocols in frame", chain.join(" · ")),
    );

    // ---- Link layer: Ethernet II ----
    let mut l3 = 0usize;
    let mut ethertype = 0u16;
    if raw.len() >= 14 {
        let mut p = 12;
        ethertype = u16be(raw, p);
        while VLAN_TPIDS.contains(&ethertype) && p + 6 <= raw.len() {
            p += 4;
            ethertype = u16be(raw, p);
        }
        l3 = p + 2;
        nodes.push(
            DetailNode::new("Ethernet II", "")
                .field("Destination", mac_str(&raw[0..6]))
                .field("Source", mac_str(&raw[6..12]))
                .field("EtherType", format!("0x{ethertype:04x}")),
        );
    }

    // ---- Network layer ----
    let mut l4 = 0usize;
    let mut ip_proto = 0u8;
    let mut have_l4 = false;
    if pkt.src_addr.is_some() || pkt.dst_addr.is_some() {
        let mut net = DetailNode::new(
            format!(
                "Internet Protocol {}",
                ip_ver.map(|v| format!("({v})")).unwrap_or_default()
            )
            .trim()
            .to_string(),
            match (pkt.src_addr, pkt.dst_addr) {
                (Some(s), Some(d)) => format!("{s} → {d}"),
                _ => String::new(),
            },
        );
        if let Some(s) = pkt.src_addr {
            net = net.field("Source address", s.to_string());
        }
        if let Some(d) = pkt.dst_addr {
            net = net.field("Destination address", d.to_string());
        }
        // Locate the transport header from the IP header length.
        if ethertype == 0x0800 && raw.len() >= l3 + 20 {
            let ihl = (raw[l3] & 0x0f) as usize * 4;
            ip_proto = raw[l3 + 9];
            net = net.field("TTL", raw[l3 + 8].to_string());
            l4 = l3 + ihl;
            have_l4 = ihl >= 20;
        } else if ethertype == 0x86dd && raw.len() >= l3 + 40 {
            ip_proto = raw[l3 + 6];
            net = net.field("Hop limit", raw[l3 + 7].to_string());
            l4 = l3 + 40;
            have_l4 = true;
        }
        nodes.push(net);
    }

    // ---- Transport layer (TCP/UDP), decoded from bytes ----
    if let Some(t) = transport {
        let mut tnode = DetailNode::new(
            t,
            match (pkt.src_port, pkt.dst_port) {
                (Some(s), Some(d)) => format!("{s} → {d}"),
                _ => String::new(),
            },
        );
        if let Some(s) = pkt.src_port {
            tnode = tnode.field("Source port", s.to_string());
        }
        if let Some(d) = pkt.dst_port {
            tnode = tnode.field("Destination port", d.to_string());
        }
        // TCP: decode the flag bits and window from byte 13/14 of the header.
        if ip_proto == 6 && have_l4 && raw.len() >= l4 + 20 {
            let seq = u32::from_be_bytes([raw[l4 + 4], raw[l4 + 5], raw[l4 + 6], raw[l4 + 7]]);
            let flags = raw[l4 + 13];
            let window = u16be(raw, l4 + 14);
            tnode = tnode
                .field("Sequence number", seq.to_string())
                .field("Flags", tcp_flag_names(flags))
                .field("Window size", window.to_string());
        } else if ip_proto == 17 && have_l4 && raw.len() >= l4 + 8 {
            let ulen = u16be(raw, l4 + 6);
            tnode = tnode.field("Length", format!("{ulen} bytes"));
        }
        if pkt.src_port.is_some() || pkt.dst_port.is_some() {
            nodes.push(tnode);
        }
    }

    // ---- Application / summary layer ----
    nodes.push(
        DetailNode::new(proto_name.clone(), "application data")
            .field("Protocol", proto_name)
            .field(
                "Info",
                if pkt.summary.is_empty() {
                    "—".into()
                } else {
                    pkt.summary.clone()
                },
            ),
    );

    // ---- netscope's plain-language explanation (its edge over Wireshark) ----
    nodes.push(DetailNode::new("What is this?", "").field("ℹ", explain_packet(pkt).to_string()));

    nodes
}

/// Human-readable TCP flag list, e.g. "SYN, ACK" (empty → "none").
fn tcp_flag_names(flags: u8) -> String {
    const BITS: [(u8, &str); 6] = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
    ];
    let set: Vec<&str> = BITS
        .iter()
        .filter(|(m, _)| flags & m != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() {
        "none".into()
    } else {
        set.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;

    /// A minimal Ethernet/IPv4/TCP SYN frame (54 bytes).
    fn syn_frame() -> Bytes {
        let mut f = vec![0u8; 54];
        // Ethernet: dst, src MACs, EtherType IPv4.
        f[0..6].copy_from_slice(&[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
        f[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        f[12] = 0x08;
        f[13] = 0x00;
        // IPv4: version/IHL, ..., proto=TCP(6), src/dst.
        f[14] = 0x45;
        f[22] = 64; // TTL
        f[23] = 6; // protocol = TCP
        f[26..30].copy_from_slice(&[192, 168, 1, 10]);
        f[30..34].copy_from_slice(&[93, 184, 216, 34]);
        // TCP: src port 50000, dst port 443, flags SYN at byte 13 of TCP header.
        let l4 = 34;
        f[l4] = 0xc3;
        f[l4 + 1] = 0x50; // 50000
        f[l4 + 2] = 0x01;
        f[l4 + 3] = 0xbb; // 443
        f[l4 + 12] = 0x50; // data offset = 5 words
        f[l4 + 13] = 0x02; // SYN
        Bytes::from(f)
    }

    fn pkt() -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: "192.168.1.10".parse().ok(),
            dst_addr: "93.184.216.34".parse().ok(),
            src_port: Some(50000),
            dst_port: Some(443),
            protocol: Protocol::Tcp,
            length: 54,
            summary: "TCP 50000 → 443 [SYN]".into(),
            data: syn_frame(),
        }
    }

    #[test]
    fn builds_full_layer_stack() {
        let nodes = build_tree(&pkt(), 0);
        let titles: Vec<&str> = nodes.iter().map(|n| n.title.as_str()).collect();
        assert_eq!(titles[0], "Frame 1");
        assert!(titles.contains(&"Ethernet II"));
        assert!(titles.iter().any(|t| t.starts_with("Internet Protocol")));
        assert!(titles.contains(&"TCP"));
        assert!(titles.contains(&"What is this?"));
    }

    #[test]
    fn decodes_ethernet_and_tcp_flags() {
        let nodes = build_tree(&pkt(), 0);
        let eth = nodes.iter().find(|n| n.title == "Ethernet II").unwrap();
        assert!(eth.fields.iter().any(|(_, v)| v == "11:22:33:44:55:66"));
        assert!(eth.fields.iter().any(|(_, v)| v == "0x0800"));
        let tcp = nodes.iter().find(|n| n.title == "TCP").unwrap();
        assert!(tcp.fields.iter().any(|(k, v)| k == "Flags" && v == "SYN"));
    }

    #[test]
    fn tolerates_empty_frame() {
        let mut p = pkt();
        p.data = Bytes::new();
        let nodes = build_tree(&p, 3);
        // Frame + network (addrs known) + application + explanation still build.
        assert!(nodes.iter().any(|n| n.title == "Frame 4"));
        assert!(nodes.iter().any(|n| n.title == "What is this?"));
    }
}
