use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openvpn_pq_cipher(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenVPN PQ Cipher (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OpenVPN") && (raw.contains("PQC") || raw.contains("pq")) {
            let end = raw.len().min(80);
            format!("OpenVPN PQ Cipher: {}", &raw[..end])
        } else if raw.contains("cipher") && raw.contains("kem") && raw.contains("openvpn") {
            let end = raw.len().min(80);
            format!("OpenVPN PQ Cipher: {}", &raw[..end])
        } else {
            format!("OpenVPN PQ Cipher ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenvpnPqCipher,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openvpn_pq_cipher_negotiation() {
        let buf = b"OpenVPN:PQC:cipher:ML-KEM-768:auth=Dilithium3";
        let r = dissect_openvpn_pq_cipher(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenvpnPqCipher);
        assert!(r.summary.contains("PQ Cipher"));
    }

    #[test]
    fn test_openvpn_pq_cipher_malformed() {
        let buf = b"short";
        let r = dissect_openvpn_pq_cipher(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
