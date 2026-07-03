use std::net::IpAddr;

use crate::models::Protocol;

use super::{dns, DissectedResult};

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

    // Dispatch application-layer protocols by port
    if src_port == 53 || dst_port == 53 {
        return dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
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
