use std::net::IpAddr;

use crate::models::Protocol;

use super::{ftp, http, imap, pop3, rdp, smtp, ssh, telnet, tls, DissectedResult};

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
}
