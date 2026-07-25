use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_hsm_kmip_2_1(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "HSM KMIP 2.1 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("KMIP") && (raw.contains("2.1") || raw.contains("key")) {
            let end = raw.len().min(80);
            format!("HSM KMIP 2.1: {}", &raw[..end])
        } else if raw.contains("Create") || raw.contains("Get") || raw.contains("Import") && raw.contains("key") {
            let end = raw.len().min(80);
            format!("HSM KMIP 2.1: {}", &raw[..end])
        } else {
            format!("HSM KMIP 2.1 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HsmKmip21,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_kmip_create_key() {
        let buf = b"KMIP:2.1:Create:key_type=RSA:length=4096";
        let r = dissect_hsm_kmip_2_1(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::HsmKmip21);
        assert!(r.summary.contains("KMIP 2.1"));
    }

    #[test]
    fn test_hsm_kmip_malformed() {
        let buf = b"tiny";
        let r = dissect_hsm_kmip_2_1(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
