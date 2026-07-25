use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_qkd_network_routing(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "QKD Network Routing (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("QKD") && (raw.contains("routing") || raw.contains("SDN")) {
            let end = raw.len().min(80);
            format!("QKD Network Routing: {}", &raw[..end])
        } else if raw.contains("Q.4160") || raw.contains("link_state") && raw.contains("trusted") {
            let end = raw.len().min(80);
            format!("QKD Network Routing: {}", &raw[..end])
        } else {
            format!("QKD Network Routing ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::QkdNetworkRouting,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkd_routing_topology() {
        let buf = b"QKD:SDN:routing:link_state:trusted:node=A";
        let r = dissect_qkd_network_routing(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::QkdNetworkRouting);
        assert!(r.summary.contains("QKD Network"));
    }

    #[test]
    fn test_qkd_routing_malformed() {
        let buf = b"short";
        let r = dissect_qkd_network_routing(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
