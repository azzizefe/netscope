use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_bfv_ciphertext(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE BFV Ciphertext (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("BFV") || raw.contains("bfv") && raw.contains("cipher") {
            let end = raw.len().min(80);
            format!("FHE BFV Ciphertext: {}", &raw[..end])
        } else if raw.contains("plaintext") && raw.contains("modulus") && raw.contains("ring") {
            let end = raw.len().min(80);
            format!("FHE BFV Ciphertext: {}", &raw[..end])
        } else {
            format!("FHE BFV Ciphertext ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheBfvCiphertext,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_bfv_ciphertext_wire() {
        let buf = b"BFV:cipher:plaintext=0xabcd:modulus=65537";
        let r = dissect_fhe_bfv_ciphertext(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheBfvCiphertext);
        assert!(r.summary.contains("BFV"));
    }

    #[test]
    fn test_fhe_bfv_ciphertext_malformed() {
        let buf = b"short";
        let r = dissect_fhe_bfv_ciphertext(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
