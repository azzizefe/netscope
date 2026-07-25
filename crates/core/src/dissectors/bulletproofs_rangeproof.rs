use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_bulletproofs_rangeproof(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Bulletproofs RangeProof (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Bulletproofs") || raw.contains("bulletproof") && raw.contains("range") {
            let end = raw.len().min(80);
            format!("Bulletproofs RangeProof: {}", &raw[..end])
        } else if raw.contains("commitment") && raw.contains("challenge") && raw.contains("response") {
            let end = raw.len().min(80);
            format!("Bulletproofs RangeProof: {}", &raw[..end])
        } else {
            format!("Bulletproofs RangeProof ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BulletproofsRangeproof,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulletproofs_rangeproof_tx() {
        let buf = b"Bulletproofs:range:commitment=V:challenge=c:response=f";
        let r = dissect_bulletproofs_rangeproof(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::BulletproofsRangeproof);
        assert!(r.summary.contains("RangeProof"));
    }

    #[test]
    fn test_bulletproofs_rangeproof_malformed() {
        let buf = b"tiny";
        let r = dissect_bulletproofs_rangeproof(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
