use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pqc_hsm_bridge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PQC HSM Bridge (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PKCS11") && (raw.contains("ML-KEM") || raw.contains("ML-DSA")) {
            let end = raw.len().min(80);
            format!("PQC HSM Bridge: {}", &raw[..end])
        } else if raw.contains("hsm_keygen") && raw.contains("pqc") {
            let end = raw.len().min(80);
            format!("PQC HSM Bridge: {}", &raw[..end])
        } else if raw.contains("C_EncapsulateKey") || raw.contains("C_DecapsulateKey") {
            let end = raw.len().min(80);
            format!("PQC HSM Bridge: {}", &raw[..end])
        } else {
            format!("PQC HSM Bridge ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PqcHsmBridge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_hsm_pkcs11() {
        let buf = b"PKCS11:C_GenerateKeyPair:ML-DSA-65:slot=0";
        let r = dissect_pqc_hsm_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcHsmBridge);
        assert!(r.summary.contains("HSM Bridge"));
    }

    #[test]
    fn test_pqc_hsm_keygen() {
        let buf = b"hsm_keygen:pqc:ML-KEM-768:session=42";
        let r = dissect_pqc_hsm_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcHsmBridge);
    }

    #[test]
    fn test_pqc_hsm_encapsulate() {
        let buf = b"C_EncapsulateKey:ML-KEM-768:ciphertext_1088B";
        let r = dissect_pqc_hsm_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcHsmBridge);
    }

    #[test]
    fn test_pqc_hsm_malformed() {
        let buf = b"ab";
        let r = dissect_pqc_hsm_bridge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
