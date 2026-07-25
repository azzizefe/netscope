use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iso_15118_v2g(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ISO 15118 V2G (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("V2G") || raw.contains("15118") || raw.contains("v2g") {
            let end = raw.len().min(80);
            format!("ISO 15118 V2G: {}", &raw[..end])
        } else if raw.contains("SessionSetup") || raw.contains("ServiceDiscovery") || raw.contains("Payment") {
            format!("ISO 15118 V2G: {}", &raw[..raw.len().min(80)])
        } else {
            format!("ISO 15118 V2G ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iso15118V2g,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_15118_v2g_session() {
        let buf = b"V2G:SessionSetup:ServiceDiscovery:Payment";
        let r = dissect_iso_15118_v2g(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Iso15118V2g);
        assert!(r.summary.contains("V2G"));
    }

    #[test]
    fn test_iso_15118_v2g_malformed() {
        let buf = b"short";
        let r = dissect_iso_15118_v2g(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
