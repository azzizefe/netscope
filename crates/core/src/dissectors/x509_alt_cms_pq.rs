use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_x509_alt_cms_pq(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "X.509 Alt CMS PQ (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CMS") && (raw.contains("PQ") || raw.contains("post-quantum")) {
            let end = raw.len().min(80);
            format!("X.509 Alt CMS PQ: {}", &raw[..end])
        } else if raw.contains("alternative") && raw.contains("signature") && raw.contains("x509") {
            let end = raw.len().min(80);
            format!("X.509 Alt CMS PQ: {}", &raw[..end])
        } else {
            format!("X.509 Alt CMS PQ ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::X509AltCmsPq,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x509_alt_cms_pq_sig() {
        let buf = b"CMS:x509:alt:PQ:ML-DSA-87:signature";
        let r = dissect_x509_alt_cms_pq(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::X509AltCmsPq);
        assert!(r.summary.contains("Alt CMS PQ"));
    }

    #[test]
    fn test_x509_alt_cms_pq_malformed() {
        let buf = b"short";
        let r = dissect_x509_alt_cms_pq(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
