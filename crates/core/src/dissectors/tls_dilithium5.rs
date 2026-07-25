use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_dilithium5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS Dilithium5 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Dilithium") || raw.contains("dilithium") || raw.contains("ML-DSA") {
            let end = raw.len().min(80);
            format!("TLS Dilithium5: {}", &raw[..end])
        } else if raw.contains("DSA") && raw.contains("post-quantum") {
            let end = raw.len().min(80);
            format!("TLS Dilithium5: {}", &raw[..end])
        } else {
            format!("TLS Dilithium5 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsDilithium5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_dilithium5_signature() {
        let buf = b"TLS:Dilithium5:ML-DSA-87:sig=0xdeadbeef";
        let r = dissect_tls_dilithium5(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsDilithium5);
        assert!(r.summary.contains("Dilithium5"));
    }

    #[test]
    fn test_tls_dilithium5_malformed() {
        let buf = b"short";
        let r = dissect_tls_dilithium5(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
