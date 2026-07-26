use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_pqc_cert_chain(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "TLS PQC Cert Chain (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("certificate_list") && (raw.contains("ML-DSA") || raw.contains("SLH-DSA")) {
            let end = raw.len().min(80);
            format!("TLS PQC Cert Chain: {}", &raw[..end])
        } else if raw.contains("composite") && raw.contains("PQC") {
            let end = raw.len().min(80);
            format!("TLS PQC Cert Chain: {}", &raw[..end])
        } else if raw.contains("Certificate") && raw.contains("Dilithium") {
            let end = raw.len().min(80);
            format!("TLS PQC Cert Chain: {}", &raw[..end])
        } else {
            format!("TLS PQC Cert Chain ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsPqcCertChain,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_cert_chain_composite() {
        let buf = b"certificate_list:ECDSA+P256:ML-DSA-87:composite";
        let r = dissect_tls_pqc_cert_chain(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcCertChain);
        assert!(r.summary.contains("Cert Chain"));
    }

    #[test]
    fn test_pqc_cert_chain_slhdsa() {
        let buf = b"Certificate:SLH-DSA-SHAKE-128S:serial=0102030405";
        let r = dissect_tls_pqc_cert_chain(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcCertChain);
    }

    #[test]
    fn test_pqc_cert_chain_malformed() {
        let buf = b"tiny";
        let r = dissect_tls_pqc_cert_chain(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
