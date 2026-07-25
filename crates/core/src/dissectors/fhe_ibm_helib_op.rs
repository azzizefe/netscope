use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_ibm_helib_op(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE IBM HELib Op (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("HELib") || raw.contains("helib") && raw.contains("operation") {
            let end = raw.len().min(80);
            format!("FHE IBM HELib Op: {}", &raw[..end])
        } else if raw.contains("mult") && raw.contains("rotate") && raw.contains("boot") {
            let end = raw.len().min(80);
            format!("FHE IBM HELib Op: {}", &raw[..end])
        } else {
            format!("FHE IBM HELib Op ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheIbmHelibOp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_ibm_helib_pipeline() {
        let buf = b"HELib:operation:mult:rotate:boot:scheme=BGV";
        let r = dissect_fhe_ibm_helib_op(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheIbmHelibOp);
        assert!(r.summary.contains("HELib"));
    }

    #[test]
    fn test_fhe_ibm_helib_malformed() {
        let buf = b"short";
        let r = dissect_fhe_ibm_helib_op(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
