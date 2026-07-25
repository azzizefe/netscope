use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_hybrid_kem(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS Hybrid KEM (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TLS") && (raw.contains("hybrid") || raw.contains("KEM")) {
            let end = raw.len().min(80);
            format!("TLS Hybrid KEM: {}", &raw[..end])
        } else if raw.contains("ECDH") && raw.contains("PQC") {
            let end = raw.len().min(80);
            format!("TLS Hybrid KEM: {}", &raw[..end])
        } else {
            format!("TLS Hybrid KEM ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsHybridKem,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_hybrid_kem_exchange() {
        let buf = b"TLS:hybrid:KEM:ECDH+X25519:PQC:ML-KEM-768";
        let r = dissect_tls_hybrid_kem(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsHybridKem);
        assert!(r.summary.contains("Hybrid KEM"));
    }

    #[test]
    fn test_tls_hybrid_kem_malformed() {
        let buf = b"short";
        let r = dissect_tls_hybrid_kem(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
