use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_hqc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS HQC (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("HQC") || raw.contains("hqc") || raw.contains("Hamming Quasi") {
            let end = raw.len().min(80);
            format!("TLS HQC: {}", &raw[..end])
        } else if raw.contains("code-based") && raw.contains("KEM") {
            let end = raw.len().min(80);
            format!("TLS HQC: {}", &raw[..end])
        } else {
            format!("TLS HQC ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsHqc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_hqc_kem() {
        let buf = b"TLS:HQC:kem:hamming:ct=0xbeef";
        let r = dissect_tls_hqc(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsHqc);
        assert!(r.summary.contains("HQC"));
    }

    #[test]
    fn test_tls_hqc_malformed() {
        let buf = b"short";
        let r = dissect_tls_hqc(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
