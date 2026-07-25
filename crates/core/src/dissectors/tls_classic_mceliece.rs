use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_classic_mceliece(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS Classic McEliece (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("McEliece") || raw.contains("mceliece") || raw.contains("Classic") {
            let end = raw.len().min(80);
            format!("TLS Classic McEliece: {}", &raw[..end])
        } else if raw.contains("code-based") && raw.contains("KEM") {
            let end = raw.len().min(80);
            format!("TLS Classic McEliece: {}", &raw[..end])
        } else {
            format!("TLS Classic McEliece ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsClassicMcEliece,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_classic_mceliece_kem() {
        let buf = b"TLS:ClassicMcEliece:kem:pk=0xabcd";
        let r = dissect_tls_classic_mceliece(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsClassicMcEliece);
        assert!(r.summary.contains("McEliece"));
    }

    #[test]
    fn test_tls_classic_mceliece_malformed() {
        let buf = b"short";
        let r = dissect_tls_classic_mceliece(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
