use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_wireguard_pq_hybrid(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "WireGuard PQ Hybrid (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("WireGuard") && (raw.contains("PQ") || raw.contains("hybrid")) {
            let end = raw.len().min(80);
            format!("WireGuard PQ Hybrid: {}", &raw[..end])
        } else if raw.contains("wg-pq") || raw.contains("wg_pq") {
            let end = raw.len().min(80);
            format!("WireGuard PQ Hybrid: {}", &raw[..end])
        } else {
            format!("WireGuard PQ Hybrid ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WireguardPqHybrid,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_pq_hybrid_handshake() {
        let buf = b"WireGuard:PQ:hybrid:wg-pq:kem=ML-KEM-768";
        let r = dissect_wireguard_pq_hybrid(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WireguardPqHybrid);
        assert!(r.summary.contains("PQ Hybrid"));
    }

    #[test]
    fn test_wireguard_pq_hybrid_malformed() {
        let buf = b"short";
        let r = dissect_wireguard_pq_hybrid(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
