use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_sphincs_plus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS SPHINCS+ (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SPHINCS") || raw.contains("sphincs") || raw.contains("SLH-DSA") {
            let end = raw.len().min(80);
            format!("TLS SPHINCS+: {}", &raw[..end])
        } else if raw.contains("hash-based") && raw.contains("signature") {
            let end = raw.len().min(80);
            format!("TLS SPHINCS+: {}", &raw[..end])
        } else {
            format!("TLS SPHINCS+ ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsSphincsPlus,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_sphincs_plus_signature() {
        let buf = b"TLS:SPHINCS+:SLH-DSA:hbs:sig=0xcafe";
        let r = dissect_tls_sphincs_plus(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsSphincsPlus);
        assert!(r.summary.contains("SPHINCS+"));
    }

    #[test]
    fn test_tls_sphincs_plus_malformed() {
        let buf = b"short";
        let r = dissect_tls_sphincs_plus(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
