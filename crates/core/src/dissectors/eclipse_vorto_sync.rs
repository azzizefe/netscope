use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_eclipse_vorto_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Eclipse Vorto Sync (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Vorto") || raw.contains("vorto") || raw.contains("information_model") {
            let end = raw.len().min(80);
            format!("Eclipse Vorto Sync: {}", &raw[..end])
        } else if raw.contains("functionblock") || raw.contains("mapping") || raw.contains("namespace") {
            format!("Eclipse Vorto Sync: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Eclipse Vorto Sync ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EclipseVortoSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eclipse_vorto_sync_model() {
        let buf = b"Vorto:information_model:functionblock:namespace";
        let r = dissect_eclipse_vorto_sync(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EclipseVortoSync);
        assert!(r.summary.contains("Vorto"));
    }

    #[test]
    fn test_eclipse_vorto_sync_malformed() {
        let buf = b"short";
        let r = dissect_eclipse_vorto_sync(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
