use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_zk_email_dkim(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "zk-email DKIM (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("zk-email") || raw.contains("zke") && raw.contains("dkim") {
            let end = raw.len().min(80);
            format!("zk-email DKIM: {}", &raw[..end])
        } else if raw.contains("DKIM") && raw.contains("regex") && raw.contains("proof") {
            let end = raw.len().min(80);
            format!("zk-email DKIM: {}", &raw[..end])
        } else {
            format!("zk-email DKIM ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZkEmailDkim,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_email_dkim_proof() {
        let buf = b"zk-email:DKIM:regex:proof:domain=example.com";
        let r = dissect_zk_email_dkim(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ZkEmailDkim);
        assert!(r.summary.contains("zk-email"));
    }

    #[test]
    fn test_zk_email_dkim_malformed() {
        let buf = b"short";
        let r = dissect_zk_email_dkim(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
