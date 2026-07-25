use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_openfhe_pke(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE OpenFHE PKE (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OpenFHE") || raw.contains("openfhe") && raw.contains("PKE") {
            let end = raw.len().min(80);
            format!("FHE OpenFHE PKE: {}", &raw[..end])
        } else if raw.contains("public_key") && raw.contains("encrypt") && raw.contains("scheme") {
            let end = raw.len().min(80);
            format!("FHE OpenFHE PKE: {}", &raw[..end])
        } else {
            format!("FHE OpenFHE PKE ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheOpenfhePke,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_openfhe_pke_api() {
        let buf = b"OpenFHE:PKE:public_key:encrypt:scheme=CKKS";
        let r = dissect_fhe_openfhe_pke(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheOpenfhePke);
        assert!(r.summary.contains("OpenFHE"));
    }

    #[test]
    fn test_fhe_openfhe_pke_malformed() {
        let buf = b"short";
        let r = dissect_fhe_openfhe_pke(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
