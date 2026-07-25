use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_autoware_zenoh(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Autoware Zenoh (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("zenoh") || raw.contains("Zenoh") || raw.contains("Zenoh") {
            let end = raw.len().min(80);
            format!("Autoware Zenoh: {}", &raw[..end])
        } else if raw.contains("autoware") || raw.contains("/aw/") || raw.contains("/planning") {
            let end = raw.len().min(80);
            format!("Autoware Zenoh: {} via zenoh", &raw[..end])
        } else {
            format!("Autoware Zenoh ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AutowareZenoh,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autoware_zenoh_pub() {
        let buf = b"zenoh:/aw/planning/trajectory:seq=42";
        let r = dissect_autoware_zenoh(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AutowareZenoh);
        assert!(r.summary.contains("Zenoh"));
    }

    #[test]
    fn test_autoware_zenoh_malformed() {
        let buf = b"ab";
        let r = dissect_autoware_zenoh(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
