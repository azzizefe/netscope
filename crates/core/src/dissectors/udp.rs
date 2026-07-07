use std::net::IpAddr;

use crate::models::Protocol;

use super::{dhcp, dns, ntp, sip, snmp, DissectedResult};

pub fn dissect_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let header = match etherparse::UdpHeader::from_slice(payload) {
        Ok((h, rest)) => (h, rest),
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown("malformed UDP".into()),
                summary: "Malformed UDP header".into(),
            };
        }
    };

    let (udp, udp_payload) = header;
    let src_port = udp.source_port;
    let dst_port = udp.destination_port;
    let on = |p: u16| src_port == p || dst_port == p;

    // Dispatch application-layer protocols by well-known port.
    if on(53) {
        return dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(5353) {
        // mDNS uses the DNS wire format; reuse the DNS dissector, then relabel.
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        r.protocol = Protocol::Mdns;
        r.summary = format!("mDNS — {}", r.summary.trim_start_matches("DNS ").trim());
        return r;
    }
    if on(67) || on(68) {
        return dhcp::dissect_dhcp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(123) {
        return ntp::dissect_ntp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(161) || on(162) {
        return snmp::dissect_snmp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(5060) || on(5061) {
        return sip::dissect_sip(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if (on(443) || on(80)) && looks_like_quic(udp_payload) {
        return quic_result(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Udp,
        summary: format!("UDP — {} bytes of payload", udp_payload.len()),
    }
}

/// Heuristic QUIC detection. QUIC's first byte has the "fixed bit" (0x40) set;
/// long-header packets (Initial/Handshake/0-RTT/Retry) also set the high bit
/// (0x80) and carry a 4-byte version. This is a heuristic, not a full parse —
/// it only runs on UDP 443/80 where QUIC is expected.
fn looks_like_quic(payload: &[u8]) -> bool {
    match payload.first() {
        // Long header: high bit + fixed bit set, plus room for the version.
        Some(b) if b & 0x80 != 0 && b & 0x40 != 0 => payload.len() >= 5,
        // Short header (1-RTT): fixed bit set, high bit clear.
        Some(b) if b & 0x40 != 0 => !payload.is_empty(),
        _ => false,
    }
}

fn quic_result(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let first = payload[0];
    let phase = if first & 0x80 == 0 {
        "1-RTT".to_string()
    } else {
        // Long-header packet-type bits (0x30) name the handshake phase.
        let kind = match (first & 0x30) >> 4 {
            0x0 => "Initial",
            0x1 => "0-RTT",
            0x2 => "Handshake",
            0x3 => "Retry",
            _ => "long-header",
        };
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if version == 0 {
            "Version Negotiation".to_string()
        } else {
            format!("{kind} (v0x{version:08x})")
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Quic,
        summary: format!("QUIC — {phase}, {} bytes", payload.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::build_udp_packet;

    #[test]
    fn udp_basic() {
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 30000, 40000, b"Hello");
        let ip_data = &data[14..];
        let (_src, _dst, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Udp);
        assert_eq!(result.src_port, Some(30000));
        assert_eq!(result.dst_port, Some(40000));
        assert!(result.summary.contains("5 bytes of payload"));
    }

    #[test]
    fn udp_dns_query_port() {
        // DNS query to port 53 should dispatch to DNS dissector
        let dns_payload = crate::dissectors::test_helpers::build_dns_query("example.com", 1234);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns_payload);
        let ip_data = &data[14..];
        let (_src, _dst, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Dns);
        assert!(result.summary.contains("example.com"));
    }

    #[test]
    fn udp_malformed() {
        let result = dissect_udp(None, None, &[0; 3]);
        assert_eq!(result.protocol, Protocol::Unknown("malformed UDP".into()));
    }
}
