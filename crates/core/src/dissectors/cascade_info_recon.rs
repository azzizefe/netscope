use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cascade_info_recon(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "CASCADE Info Recon (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CASCADE") || raw.contains("cascade") && raw.contains("reconciliation") {
            let end = raw.len().min(80);
            format!("CASCADE Info Recon: {}", &raw[..end])
        } else if raw.contains("parity") && raw.contains("block") && raw.contains("iteration") {
            let end = raw.len().min(80);
            format!("CASCADE Info Recon: {}", &raw[..end])
        } else {
            format!("CASCADE Info Recon ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CascadeInfoRecon,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cascade_reconciliation() {
        let buf = b"CASCADE:parity:block=7:iteration=3:parity=0x1f";
        let r = dissect_cascade_info_recon(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CascadeInfoRecon);
        assert!(r.summary.contains("CASCADE"));
    }

    #[test]
    fn test_cascade_recon_malformed() {
        let buf = b"short";
        let r = dissect_cascade_info_recon(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
