use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_ckks_serialize(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE CKKS Serialize (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CKKS") || raw.contains("ckks") && raw.contains("ciphertext") {
            let end = raw.len().min(80);
            format!("FHE CKKS Serialize: {}", &raw[..end])
        } else if raw.contains("real") && raw.contains("imag") && raw.contains("slot") {
            let end = raw.len().min(80);
            format!("FHE CKKS Serialize: {}", &raw[..end])
        } else {
            format!("FHE CKKS Serialize ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheCkksSerialize,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_ckks_serialize_ct() {
        let buf = b"CKKS:ciphertext:real=1.23:imag=4.56:slot=8";
        let r = dissect_fhe_ckks_serialize(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheCkksSerialize);
        assert!(r.summary.contains("CKKS"));
    }

    #[test]
    fn test_fhe_ckks_serialize_malformed() {
        let buf = b"short";
        let r = dissect_fhe_ckks_serialize(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
