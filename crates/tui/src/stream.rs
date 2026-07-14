//! Follow TCP/UDP Stream for the TUI (ROADMAP §6.1) — the terminal counterpart
//! of the desktop's "Follow Stream". Given the selected packet, it gathers
//! every packet in the ring belonging to the same conversation (the two
//! endpoints, either direction), strips the Ethernet/IP/transport headers, and
//! returns the application payload as directional, human-readable chunks.

use std::collections::VecDeque;
use std::net::IpAddr;

use netscope_core::models::Packet;

/// One side's contribution to the conversation.
pub struct StreamChunk {
    /// True when this payload went client → server (the side that owns the
    /// selected packet's source endpoint).
    pub from_client: bool,
    /// Payload rendered as text (printable ASCII kept, other bytes → `·`).
    pub text: String,
}

/// A reconstructed conversation ready to render in the Follow-Stream overlay.
pub struct FollowStream {
    pub client: String,
    pub server: String,
    pub client_bytes: usize,
    pub server_bytes: usize,
    pub chunks: Vec<StreamChunk>,
}

/// The two endpoints of a conversation, order-independent, so a packet in
/// either direction maps to the same key.
type Endpoint = (Option<IpAddr>, Option<u16>);

fn endpoints(pkt: &Packet) -> (Endpoint, Endpoint) {
    ((pkt.src_addr, pkt.src_port), (pkt.dst_addr, pkt.dst_port))
}

/// Do two packets belong to the same conversation (same unordered endpoint
/// pair)? Endpoints must be fully addressed for a match.
fn same_conversation(a: &Packet, b: &Packet) -> bool {
    let (a1, a2) = endpoints(a);
    let (b1, b2) = endpoints(b);
    if a1.0.is_none() || a2.0.is_none() {
        return false;
    }
    (a1 == b1 && a2 == b2) || (a1 == b2 && a2 == b1)
}

/// Build the Follow-Stream view for the conversation the packet at `selected`
/// belongs to. Returns `None` if the selection has no addressed endpoints.
pub fn follow(packets: &VecDeque<Packet>, selected: usize) -> Option<FollowStream> {
    let sel = packets.get(selected)?;
    if sel.src_addr.is_none() || sel.dst_addr.is_none() {
        return None;
    }
    let (client_ep, server_ep) = endpoints(sel);

    let mut chunks = Vec::new();
    let mut client_bytes = 0;
    let mut server_bytes = 0;

    for p in packets {
        if !same_conversation(sel, p) {
            continue;
        }
        let payload = match extract_payload(p) {
            Some(pl) if !pl.is_empty() => pl,
            _ => continue,
        };
        let from_client = endpoints(p).0 == client_ep;
        if from_client {
            client_bytes += payload.len();
        } else {
            server_bytes += payload.len();
        }
        chunks.push(StreamChunk {
            from_client,
            text: decode_stream_text(payload, &p.protocol),
        });
    }

    Some(FollowStream {
        client: fmt_endpoint(client_ep),
        server: fmt_endpoint(server_ep),
        client_bytes,
        server_bytes,
        chunks,
    })
}

fn fmt_endpoint((addr, port): Endpoint) -> String {
    match (addr, port) {
        (Some(a), Some(p)) => netscope_core::models::format_endpoint(a, Some(p)),
        (Some(a), None) => a.to_string(),
        _ => "?".into(),
    }
}

/// Strip Ethernet (+ one VLAN tag) + IPv4/IPv6 + TCP/UDP headers, returning the
/// application payload. Mirrors the desktop's `extractPayload`.
fn extract_payload(pkt: &Packet) -> Option<&[u8]> {
    let raw = pkt.data.as_ref();
    if raw.len() < 14 {
        return None;
    }
    let mut o = 14;
    let mut ethertype = ((raw[12] as u16) << 8) | raw[13] as u16;
    if matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if raw.len() < 18 {
            return None;
        }
        ethertype = ((raw[16] as u16) << 8) | raw[17] as u16;
        o = 18;
    }
    let proto = if ethertype == 0x0800 {
        if raw.len() < o + 20 {
            return None;
        }
        let ihl = (raw[o] & 0x0f) as usize * 4;
        let p = raw[o + 9];
        o += ihl.max(20);
        p
    } else if ethertype == 0x86dd {
        if raw.len() < o + 40 {
            return None;
        }
        let p = raw[o + 6];
        o += 40;
        p
    } else {
        return None;
    };
    if proto == 6 {
        if raw.len() < o + 20 {
            return None;
        }
        let doff = ((raw[o + 12] >> 4) as usize & 0x0f) * 4;
        o += doff.max(20);
    } else if proto == 17 {
        if raw.len() < o + 8 {
            return None;
        }
        o += 8;
    } else {
        return None;
    }
    if o <= raw.len() {
        Some(&raw[o..])
    } else {
        None
    }
}

/// Bytes → text the way Wireshark's stream view does: printable ASCII, tabs
/// and newlines kept; everything else becomes a middle dot.
fn decode_plain_stream(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            9 | 10 | 13 => b as char,
            32..=126 => b as char,
            _ => '·',
        })
        .collect()
}

fn decode_http2_stream(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut off = 0;
    if bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        out.push_str("[HTTP/2 Connection Preface]\n");
        off += 24;
    }
    
    let mut frame_count = 0;
    while off + 9 <= bytes.len() {
        let len = ((bytes[off] as usize) << 16) | ((bytes[off+1] as usize) << 8) | (bytes[off+2] as usize);
        let typ = bytes[off+3];
        let flags = bytes[off+4];
        let stream_id = u32::from_be_bytes([bytes[off+5] & 0x7f, bytes[off+6], bytes[off+7], bytes[off+8]]);
        
        let type_name = match typ {
            0 => "DATA",
            1 => "HEADERS",
            2 => "PRIORITY",
            3 => "RST_STREAM",
            4 => "SETTINGS",
            5 => "PUSH_PROMISE",
            6 => "PING",
            7 => "GOAWAY",
            8 => "WINDOW_UPDATE",
            9 => "CONTINUATION",
            _ => "UNKNOWN",
        };
        
        out.push_str(&format!("HTTP/2 Frame: {} (Stream {}, Length: {}, Flags: 0x{:02x})\n", type_name, stream_id, len, flags));
        
        let payload_start = off + 9;
        let payload_end = (payload_start + len).min(bytes.len());
        if payload_end > payload_start {
            let payload = &bytes[payload_start..payload_end];
            if typ == 0 {
                let txt = decode_plain_stream(payload);
                if !txt.is_empty() {
                    out.push_str(&format!("  Data: {}\n", txt.chars().take(200).collect::<String>()));
                }
            } else if typ == 1 {
                let txt = decode_plain_stream(payload);
                if !txt.is_empty() {
                    out.push_str(&format!("  Headers (Huffman/Raw): {}\n", txt.chars().take(200).collect::<String>()));
                }
            }
        }
        
        off += 9 + len;
        frame_count += 1;
        if frame_count > 50 {
            out.push_str("... (truncated HTTP/2 frames)\n");
            break;
        }
    }
    
    if out.is_empty() {
        decode_plain_stream(bytes)
    } else {
        out
    }
}

fn decode_tls_stream(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut off = 0;
    let mut record_count = 0;
    
    while off + 5 <= bytes.len() {
        let content_type = bytes[off];
        let version_major = bytes[off+1];
        let version_minor = bytes[off+2];
        let len = u16::from_be_bytes([bytes[off+3], bytes[off+4]]) as usize;
        
        let type_name = match content_type {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            24 => "Heartbeat",
            _ => break,
        };
        
        let version_str = match (version_major, version_minor) {
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            (3, 0) => "SSL 3.0",
            _ => "Unknown TLS",
        };
        
        if content_type == 22 && off + 6 <= bytes.len() {
            let handshake_type = bytes[off+5];
            let hs_name = match handshake_type {
                1 => "ClientHello",
                2 => "ServerHello",
                4 => "NewSessionTicket",
                8 => "EncryptedExtensions",
                11 => "Certificate",
                12 => "ServerKeyExchange",
                13 => "CertificateRequest",
                14 => "ServerHelloDone",
                15 => "CertificateVerify",
                16 => "ClientKeyExchange",
                20 => "Finished",
                _ => "Other Handshake",
            };
            out.push_str(&format!("TLS Record: Handshake - {} ({}, Length: {})\n", hs_name, version_str, len));
        } else {
            out.push_str(&format!("TLS Record: {} ({}, Length: {})\n", type_name, version_str, len));
        }
        
        off += 5 + len;
        record_count += 1;
        if record_count > 50 {
            out.push_str("... (truncated TLS records)\n");
            break;
        }
    }
    
    if out.is_empty() {
        decode_plain_stream(bytes)
    } else {
        out
    }
}

fn decode_quic_stream(bytes: &[u8]) -> String {
    let mut out = String::new();
    if bytes.is_empty() {
        return out;
    }
    let first = bytes[0];
    if first & 0x80 != 0 {
        let version = if bytes.len() >= 5 {
            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
        } else {
            0
        };
        let packet_type = (first >> 4) & 3;
        let type_name = match packet_type {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            3 => "Retry",
            _ => "Unknown",
        };
        out.push_str(&format!("QUIC Long Header Packet: {} (Version: 0x{:08x}, Length: {})\n", type_name, version, bytes.len()));
    } else {
        let spin = if first & 0x20 != 0 { "Spin" } else { "NoSpin" };
        out.push_str(&format!("QUIC Short Header Packet (1-RTT, Encrypted, {}, Length: {})\n", spin, bytes.len()));
    }
    out
}

fn decode_stream_text(bytes: &[u8], proto: &netscope_core::models::Protocol) -> String {
    match proto {
        netscope_core::models::Protocol::Http2 => decode_http2_stream(bytes),
        netscope_core::models::Protocol::Tls => decode_tls_stream(bytes),
        netscope_core::models::Protocol::Quic => decode_quic_stream(bytes),
        _ => decode_plain_stream(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;
    use netscope_core::models::Protocol;

    /// Ethernet/IPv4/TCP frame carrying `payload` from `sport`→`dport`.
    fn http_frame(sport: u16, dport: u16, payload: &[u8]) -> Bytes {
        let mut f = vec![0u8; 54];
        f[12] = 0x08; // IPv4
        f[14] = 0x45;
        f[23] = 6; // TCP
        f[26..30].copy_from_slice(&[192, 168, 1, 5]);
        f[30..34].copy_from_slice(&[93, 184, 216, 34]);
        let l4 = 34;
        f[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
        f[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
        f[l4 + 12] = 0x50; // data offset 5 words
        f.extend_from_slice(payload);
        Bytes::from(f)
    }

    fn pkt(src: &str, sport: u16, dst: &str, dport: u16, payload: &[u8]) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: src.parse().ok(),
            dst_addr: dst.parse().ok(),
            src_port: Some(sport),
            dst_port: Some(dport),
            protocol: Protocol::Http,
            length: 54 + payload.len(),
            summary: "HTTP".into(),
            data: http_frame(sport, dport, payload),
        }
    }

    #[test]
    fn reconstructs_bidirectional_conversation() {
        let mut q = VecDeque::new();
        q.push_back(pkt(
            "192.168.1.5",
            50000,
            "93.184.216.34",
            80,
            b"GET / HTTP/1.1\r\n",
        ));
        q.push_back(pkt(
            "93.184.216.34",
            80,
            "192.168.1.5",
            50000,
            b"HTTP/1.1 200 OK\r\n",
        ));
        // An unrelated packet must not leak in.
        q.push_back(pkt("10.0.0.1", 1, "10.0.0.2", 2, b"nope"));

        let s = follow(&q, 0).expect("stream");
        assert_eq!(s.chunks.len(), 2);
        assert!(s.chunks[0].from_client);
        assert!(!s.chunks[1].from_client);
        assert!(s.chunks[0].text.contains("GET /"));
        assert!(s.chunks[1].text.contains("200 OK"));
        assert!(s.client_bytes > 0 && s.server_bytes > 0);
    }

    #[test]
    fn none_without_addresses() {
        let mut q = VecDeque::new();
        let mut p = pkt("192.168.1.5", 1, "10.0.0.2", 2, b"x");
        p.src_addr = None;
        q.push_back(p);
        assert!(follow(&q, 0).is_none());
    }
}
