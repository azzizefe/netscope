use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_wireguard_kyber_poly(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "WireGuard Kyber+Poly1305 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Kyber") && (raw.contains("Poly1305") || raw.contains("poly")) {
            let end = raw.len().min(80);
            format!("WireGuard Kyber+Poly: {}", &raw[..end])
        } else if raw.contains("WireGuard") && raw.contains("Kyber") {
            let end = raw.len().min(80);
            format!("WireGuard Kyber+Poly: {}", &raw[..end])
        } else {
            format!("WireGuard Kyber+Poly ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WireguardKyberPoly,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_kyber_poly_handshake() {
        let buf = b"WireGuard:Kyber:Poly1305:kem=ML-KEM-768";
        let r = dissect_wireguard_kyber_poly(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WireguardKyberPoly);
        assert!(r.summary.contains("Kyber+Poly"));
    }

    #[test]
    fn test_wireguard_kyber_poly_malformed() {
        let buf = b"short";
        let r = dissect_wireguard_kyber_poly(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
