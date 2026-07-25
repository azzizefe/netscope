use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_kyber1024(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS Kyber-1024 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Kyber") || raw.contains("kyber") || raw.contains("ML-KEM") {
            let end = raw.len().min(80);
            format!("TLS Kyber-1024: {}", &raw[..end])
        } else if raw.contains("KEM") && (raw.contains("1024") || raw.contains("ML-KEM-1024")) {
            let end = raw.len().min(80);
            format!("TLS Kyber-1024: {}", &raw[..end])
        } else {
            format!("TLS Kyber-1024 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsKyber1024,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_kyber1024_key_exchange() {
        let buf = b"TLS:Kyber-1024:ML-KEM-1024:ct=0xabcd";
        let r = dissect_tls_kyber1024(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsKyber1024);
        assert!(r.summary.contains("Kyber-1024"));
    }

    #[test]
    fn test_tls_kyber1024_malformed() {
        let buf = b"short";
        let r = dissect_tls_kyber1024(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
