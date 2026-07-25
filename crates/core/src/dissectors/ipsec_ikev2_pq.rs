use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ipsec_ikev2_pq(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "IKEv2 PQ (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("IKEv2") && (raw.contains("PQ") || raw.contains("PQC")) {
            let end = raw.len().min(80);
            format!("IKEv2 PQ DH: {}", &raw[..end])
        } else if raw.contains("RFC 9382") || raw.contains("PQC group") || raw.contains("ike_pq") {
            let end = raw.len().min(80);
            format!("IKEv2 PQ DH: {}", &raw[..end])
        } else {
            format!("IKEv2 PQ DH ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IpsecIkev2Pq,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_ikev2_pq_exchange() {
        let buf = b"IKEv2:PQC:group=ML-KEM-768:SArsp=0xabc";
        let r = dissect_ipsec_ikev2_pq(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IpsecIkev2Pq);
        assert!(r.summary.contains("IKEv2 PQ"));
    }

    #[test]
    fn test_ipsec_ikev2_pq_malformed() {
        let buf = b"tiny";
        let r = dissect_ipsec_ikev2_pq(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
