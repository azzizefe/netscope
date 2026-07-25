use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pkcs11_3_1(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PKCS#11 v3.1 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PKCS11") || raw.contains("pkcs11") && raw.contains("token") {
            let end = raw.len().min(80);
            format!("PKCS#11 v3.1: {}", &raw[..end])
        } else if raw.contains("C_Encrypt") || raw.contains("C_Decrypt") || raw.contains("C_Sign") {
            let end = raw.len().min(80);
            format!("PKCS#11 v3.1: {}", &raw[..end])
        } else {
            format!("PKCS#11 v3.1 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pkcs1131,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs11_3_1_encrypt() {
        let buf = b"PKCS11:v3.1:C_Encrypt:slot=1:key=0xabc";
        let r = dissect_pkcs11_3_1(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Pkcs1131);
        assert!(r.summary.contains("PKCS#11"));
    }

    #[test]
    fn test_pkcs11_3_1_malformed() {
        let buf = b"short";
        let r = dissect_pkcs11_3_1(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
