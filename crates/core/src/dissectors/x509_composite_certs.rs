use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_x509_composite_certs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "X.509 Composite Certs (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("X.509") && (raw.contains("composite") || raw.contains("hybrid")) {
            let end = raw.len().min(80);
            format!("X.509 Composite Certs: {}", &raw[..end])
        } else if raw.contains("Certificate") && raw.contains("PQ") && raw.contains("traditional") {
            let end = raw.len().min(80);
            format!("X.509 Composite Certs: {}", &raw[..end])
        } else {
            format!("X.509 Composite Certs ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::X509CompositeCerts,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x509_composite_cert() {
        let buf = b"X.509:composite:ECDSA+ML-DSA-87:serial=123";
        let r = dissect_x509_composite_certs(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::X509CompositeCerts);
        assert!(r.summary.contains("Composite"));
    }

    #[test]
    fn test_x509_composite_certs_malformed() {
        let buf = b"short";
        let r = dissect_x509_composite_certs(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
