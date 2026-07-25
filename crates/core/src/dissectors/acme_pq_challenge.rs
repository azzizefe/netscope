use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_acme_pq_challenge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ACME PQ Challenge (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("ACME") && (raw.contains("PQ") || raw.contains("hybrid")) {
            let end = raw.len().min(80);
            format!("ACME PQ Challenge: {}", &raw[..end])
        } else if raw.contains("challenge") && raw.contains("domain") && raw.contains("pq") {
            let end = raw.len().min(80);
            format!("ACME PQ Challenge: {}", &raw[..end])
        } else {
            format!("ACME PQ Challenge ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AcmePqChallenge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_pq_challenge_req() {
        let buf = b"ACME:PQ:challenge:domain=example.com:token=xyz";
        let r = dissect_acme_pq_challenge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AcmePqChallenge);
        assert!(r.summary.contains("ACME PQ"));
    }

    #[test]
    fn test_acme_pq_challenge_malformed() {
        let buf = b"short";
        let r = dissect_acme_pq_challenge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
