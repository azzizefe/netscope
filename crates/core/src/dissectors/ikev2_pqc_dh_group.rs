use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ikev2_pqc_dh_group(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "IKEv2 PQC DH Group (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SA") && (raw.contains("ML-KEM") || raw.contains("FrodoKEM")) {
            let end = raw.len().min(80);
            format!("IKEv2 PQC DH Group: {}", &raw[..end])
        } else if raw.contains("Transform") && raw.contains("PQC") {
            let end = raw.len().min(80);
            format!("IKEv2 PQC DH Group: {}", &raw[..end])
        } else if raw.contains("DH_GROUP") && (raw.contains("kyber") || raw.contains("frodo")) {
            let end = raw.len().min(80);
            format!("IKEv2 PQC DH Group: {}", &raw[..end])
        } else {
            format!("IKEv2 PQC DH Group ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ikev2PqcDhGroup,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ikev2_pqc_dh_sa() {
        let buf = b"SA:ML-KEM-768:Transform:AES-GCM-256";
        let r = dissect_ikev2_pqc_dh_group(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ikev2PqcDhGroup);
        assert!(r.summary.contains("DH Group"));
    }

    #[test]
    fn test_ikev2_pqc_dh_group_transform() {
        let buf = b"Transform:PQC:DH_GROUP_ML_KEM_768";
        let r = dissect_ikev2_pqc_dh_group(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ikev2PqcDhGroup);
    }

    #[test]
    fn test_ikev2_pqc_dh_frodo() {
        let buf = b"DH_GROUP:frodo-1344-AES:Transform";
        let r = dissect_ikev2_pqc_dh_group(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ikev2PqcDhGroup);
    }

    #[test]
    fn test_ikev2_pqc_dh_malformed() {
        let buf = b"short";
        let r = dissect_ikev2_pqc_dh_group(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
