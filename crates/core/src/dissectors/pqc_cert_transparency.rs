use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pqc_cert_transparency(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "PQC Cert Transparency (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SCT") && (raw.contains("ML-DSA") || raw.contains("SLH-DSA")) {
            let end = raw.len().min(80);
            format!("PQC Cert Transparency: {}", &raw[..end])
        } else if raw.contains("certificate_timestamp") && raw.contains("PQ") {
            let end = raw.len().min(80);
            format!("PQC Cert Transparency: {}", &raw[..end])
        } else if raw.contains("sct_list") && raw.contains("hybrid") {
            let end = raw.len().min(80);
            format!("PQC Cert Transparency: {}", &raw[..end])
        } else {
            format!("PQC Cert Transparency ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PqcCertTransparency,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_ct_sct() {
        let buf = b"SCT:ML-DSA-65:timestamp=1700000000:log_id=abcdef";
        let r = dissect_pqc_cert_transparency(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcCertTransparency);
        assert!(r.summary.contains("Cert Transparency"));
    }

    #[test]
    fn test_pqc_ct_timestamp() {
        let buf = b"certificate_timestamp:PQ:SLH-DSA-SHAKE-128S:entry=1";
        let r = dissect_pqc_cert_transparency(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcCertTransparency);
    }

    #[test]
    fn test_pqc_ct_sct_list() {
        let buf = b"sct_list:hybrid:ML-DSA-65+ECDSA-P256:count=3";
        let r = dissect_pqc_cert_transparency(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PqcCertTransparency);
    }

    #[test]
    fn test_pqc_ct_malformed() {
        let buf = b"short";
        let r = dissect_pqc_cert_transparency(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
