use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_apple_aneclientd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Apple ANEClientd (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("ane_client") || raw.contains("ANEClient") {
            let end = raw.len().min(80);
            format!("Apple ANEClientd: {}", &raw[..end])
        } else if raw.contains("neural_engine") || raw.contains("ane_pipeline") {
            format!("Apple ANEClientd: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Apple ANEClientd ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AppleAneclientd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_aneclientd_request() {
        let buf = b"ane_client:inference:neural_engine_pipeline";
        let r = dissect_apple_aneclientd(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AppleAneclientd);
        assert!(r.summary.contains("ane_client"));
    }

    #[test]
    fn test_apple_aneclientd_malformed() {
        let buf = b"short";
        let r = dissect_apple_aneclientd(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
