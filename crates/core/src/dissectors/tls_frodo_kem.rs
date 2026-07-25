use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_frodo_kem(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS FrodoKEM (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Frodo") || raw.contains("frodo") || raw.contains("FrodoKEM") {
            let end = raw.len().min(80);
            format!("TLS FrodoKEM: {}", &raw[..end])
        } else if raw.contains("AES") && raw.contains("hybrid") && raw.contains("KEM") {
            let end = raw.len().min(80);
            format!("TLS FrodoKEM: {}", &raw[..end])
        } else {
            format!("TLS FrodoKEM ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsFrodoKem,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_frodo_kem_exchange() {
        let buf = b"TLS:FrodoKEM-1344-AES:ct=0x1234";
        let r = dissect_tls_frodo_kem(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsFrodoKem);
        assert!(r.summary.contains("FrodoKEM"));
    }

    #[test]
    fn test_tls_frodo_kem_malformed() {
        let buf = b"short";
        let r = dissect_tls_frodo_kem(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
