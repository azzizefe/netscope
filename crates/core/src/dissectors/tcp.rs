use std::net::IpAddr;

use crate::models::Protocol;

use super::{
    bgp, cassandra, dnp3, enip, ftp, http, http2, imap, kerberos, ldap, modbus, mongodb, mqtt,
    mysql, opcua, openvpn, pop3, postgres, rdp, redis, smtp, ssh, telnet, tls, websocket,
    DissectedResult,
};

pub fn dissect_tcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let header = match etherparse::TcpHeader::from_slice(payload) {
        Ok((h, rest)) => (h, rest),
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown("malformed TCP".into()),
                summary: "Malformed TCP header".into(),
            };
        }
    };

    let (tcp, tcp_payload) = header;
    let src_port = tcp.source_port;
    let dst_port = tcp.destination_port;

    let syn = tcp.syn;
    let ack = tcp.ack;
    let fin = tcp.fin;
    let rst = tcp.rst;

    let summary = if syn && !ack {
        "TCP Connection opened (3-way handshake)".into()
    } else if syn && ack {
        "TCP SYN-ACK — handshake in progress".into()
    } else if fin {
        "TCP Connection closing (FIN)".into()
    } else if rst {
        "TCP Connection reset (RST)".into()
    } else if !tcp_payload.is_empty() {
        // Try application-layer dissection by well-known port.
        let on = |p: u16| src_port == p || dst_port == p;
        if on(80) {
            // h2c with prior knowledge sends the HTTP/2 preface straight to
            // port 80 — check for it before assuming HTTP/1.x.
            if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
                return h2;
            }
            return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(443) {
            return tls::dissect_tls(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(22) {
            return ssh::dissect_ssh(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(21) {
            return ftp::dissect_ftp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(25) || on(587) {
            return smtp::dissect_smtp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(143) {
            return imap::dissect_imap(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(110) {
            return pop3::dissect_pop3(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(23) {
            return telnet::dissect_telnet(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3389) {
            return rdp::dissect_rdp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Database wire protocols (ROADMAP §3.4).
        if on(5432) {
            return postgres::dissect_postgres(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3306) {
            return mysql::dissect_mysql(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(27017) {
            return mongodb::dissect_mongodb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6379) {
            return redis::dissect_redis(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(9042) {
            return cassandra::dissect_cassandra(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Industrial / OT protocols (ROADMAP §3.5).
        if on(502) {
            return modbus::dissect_modbus(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(20000) {
            return dnp3::dissect_dnp3(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(44818) {
            return enip::dissect_enip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4840) {
            return opcua::dissect_opcua(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Security / auth / VPN protocols (ROADMAP §3.7).
        if on(88) {
            return kerberos::dissect_kerberos(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(389) {
            return ldap::dissect_ldap(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1194) {
            return openvpn::dissect_openvpn(src_ip, dst_ip, src_port, dst_port, tcp_payload, true);
        }
        // IoT messaging (ROADMAP §3.8).
        if on(1883) {
            return mqtt::dissect_mqtt(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Operator / routing protocols (ROADMAP §3.3).
        if on(179) {
            return bgp::dissect_bgp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // WebSocket and HTTP/2 (h2c) live on no fixed port (an HTTP connection
        // is upgraded in place, or the h2c preface opens any port), so their
        // traffic can show up anywhere. Route upgrade handshakes through the
        // HTTP dissector even off port 80, and report strictly-validated
        // WebSocket frame chains / HTTP/2 frame chains as themselves.
        // upgrade_note only reads the header block, so validate just the
        // first 2 KiB instead of UTF-8-scanning every payload (ROADMAP §4.1).
        let head = &tcp_payload[..tcp_payload.len().min(2048)];
        if let Ok(text) = std::str::from_utf8(head) {
            if websocket::upgrade_note(text).is_some() || http2::upgrade_note(text).is_some() {
                return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
            }
        }
        if let Some(ws) = websocket::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
            return ws;
        }
        if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
            return h2;
        }
        // User-defined plugins claim what no built-in dissector recognised
        // (see crate::plugins) — they never shadow the protocols above.
        if let Some(p) = crate::plugins::try_dissect(
            crate::plugins::TransportKind::Tcp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_payload,
        ) {
            return p;
        }
        format!("TCP — {} bytes of payload", tcp_payload.len())
    } else {
        "TCP — no payload (keep-alive or ACK)".into()
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::build_tcp_packet;

    #[test]
    fn tcp_syn() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            true,
            false,
            false,
            false,
            &[],
        );
        // We need only the TCP portion (after IP header)
        // IP header is 20 bytes, so skip that
        let ip_data = &data[14..]; // skip ethernet
        let (_ip_src, _ip_dst, _proto, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.src_port, Some(12345));
        assert_eq!(result.dst_port, Some(80));
        assert_eq!(result.summary, "TCP Connection opened (3-way handshake)");
    }

    #[test]
    fn tcp_fin() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            false,
            false,
            true,
            false,
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP Connection closing (FIN)");
    }

    #[test]
    fn tcp_rst() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            false,
            false,
            false,
            true,
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP Connection reset (RST)");
    }

    #[test]
    fn tcp_syn_ack() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            true,
            true,
            false,
            false,
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP SYN-ACK — handshake in progress");
    }

    #[test]
    fn tcp_data_no_payload() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            false,
            true,
            false,
            false,
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP — no payload (keep-alive or ACK)");
    }

    #[test]
    fn tcp_malformed() {
        let result = dissect_tcp(None, None, &[0; 3]);
        assert_eq!(result.protocol, Protocol::Unknown("malformed TCP".into()));
        assert!(result.src_port.is_none());
    }

    /// Run a payload through dissect_tcp on an arbitrary (non-well-known) port.
    fn dissect_payload_on_port_8080(payload: &[u8]) -> super::DissectedResult {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            8080,
            false,
            true,
            false,
            false,
            payload,
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        )
    }

    #[test]
    fn websocket_frames_detected_on_any_port() {
        // Unmasked text frame "hi": FIN|text, len 2.
        let result = dissect_payload_on_port_8080(&[0x81, 0x02, b'h', b'i']);
        assert_eq!(result.protocol, Protocol::WebSocket);
        assert_eq!(result.summary, "WebSocket Text — \"hi\"");
    }

    #[test]
    fn websocket_handshake_routed_to_http_on_any_port() {
        let req = b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\n\r\n";
        let result = dissect_payload_on_port_8080(req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(
            result.summary,
            "HTTP GET /chat (HTTP/1.1) — WebSocket handshake"
        );
    }

    #[test]
    fn plain_payload_on_odd_port_stays_tcp() {
        let result = dissect_payload_on_port_8080(b"just some application bytes");
        assert_eq!(result.protocol, Protocol::Tcp);
        assert!(result.summary.starts_with("TCP —"));
    }

    #[test]
    fn http2_frames_detected_on_any_port() {
        // SETTINGS ACK: len 0, type 0x4, flags 0x1, stream 0.
        let result = dissect_payload_on_port_8080(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]);
        assert_eq!(result.protocol, Protocol::Http2);
        assert_eq!(result.summary, "HTTP/2 SETTINGS ACK");
    }

    #[test]
    fn http2_preface_detected_on_port_80() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            80,
            false,
            true,
            false,
            false,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Http2);
        assert_eq!(result.summary, "HTTP/2 connection preface");
    }

    #[test]
    fn grpc_message_detected_on_any_port() {
        // DATA frame (stream 1, END_STREAM) carrying one complete gRPC
        // message: flag 0 + length 3 + 3 payload bytes.
        let mut payload = vec![0, 0, 8, 0x0, 0x1, 0, 0, 0, 1];
        payload.extend([0u8, 0, 0, 0, 3, 7, 7, 7]);
        let result = dissect_payload_on_port_8080(&payload);
        assert_eq!(result.protocol, Protocol::Grpc);
        assert_eq!(
            result.summary,
            "gRPC message — 3 bytes (uncompressed) on stream 1"
        );
    }

    #[test]
    fn h2c_upgrade_routed_to_http_on_any_port() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";
        let result = dissect_payload_on_port_8080(req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(
            result.summary,
            "HTTP GET / (HTTP/1.1) — HTTP/2 upgrade (h2c)"
        );
    }
}
