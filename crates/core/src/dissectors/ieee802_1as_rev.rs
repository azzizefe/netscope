use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ieee802_1as_rev(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "802.1AS-Rev gPTP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("gPTP") || raw.contains("802.1AS") || raw.contains("as_rev") {
            let end = raw.len().min(80);
            format!("802.1AS-Rev gPTP: {}", &raw[..end])
        } else if raw.contains("sync") || raw.contains("follow_up") || raw.contains("delay_req") {
            format!("802.1AS-Rev gPTP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("802.1AS-Rev gPTP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee8021asRev,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee802_1as_rev_gptp() {
        let buf = b"gPTP:802.1AS:sync:follow_up";
        let r = dissect_ieee802_1as_rev(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ieee8021asRev);
        assert!(r.summary.contains("gPTP"));
    }

    #[test]
    fn test_ieee802_1as_rev_malformed() {
        let buf = b"short";
        let r = dissect_ieee802_1as_rev(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
