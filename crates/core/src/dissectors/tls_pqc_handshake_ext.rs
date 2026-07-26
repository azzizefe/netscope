use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_pqc_handshake_ext(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS PQC Handshake Ext (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("supported_groups") && (raw.contains("ML-KEM") || raw.contains("Kyber")) {
            let end = raw.len().min(80);
            format!("TLS PQC Handshake Ext: {}", &raw[..end])
        } else if raw.contains("key_share") && raw.contains("PQC") {
            let end = raw.len().min(80);
            format!("TLS PQC Handshake Ext: {}", &raw[..end])
        } else if raw.contains("signature_algorithms") && raw.contains("Dilithium") {
            let end = raw.len().min(80);
            format!("TLS PQC Handshake Ext: {}", &raw[..end])
        } else {
            format!("TLS PQC Handshake Ext ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsPqcHandshakeExt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_handshake_ext_supported_groups() {
        let buf = b"supported_groups:ML-KEM-768,Kyber1024,X25519";
        let r = dissect_tls_pqc_handshake_ext(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcHandshakeExt);
        assert!(r.summary.contains("Handshake Ext"));
    }

    #[test]
    fn test_pqc_handshake_ext_key_share() {
        let buf = b"key_share:PQC:ML-KEM-768:0102030405060708";
        let r = dissect_tls_pqc_handshake_ext(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcHandshakeExt);
    }

    #[test]
    fn test_pqc_handshake_ext_signature_algorithms() {
        let buf = b"signature_algorithms:Dilithium5,SLH-DSA-SHAKE-128S";
        let r = dissect_tls_pqc_handshake_ext(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcHandshakeExt);
    }

    #[test]
    fn test_pqc_handshake_ext_malformed() {
        let buf = b"short";
        let r = dissect_tls_pqc_handshake_ext(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
