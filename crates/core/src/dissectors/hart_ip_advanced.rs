use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_hart_ip_advanced(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "HART-IP Advanced (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("HART") && (raw.contains("IP") || raw.contains("wireless")) {
            let end = raw.len().min(80);
            format!("HART-IP Advanced: {}", &raw[..end])
        } else if raw.contains("WirelessHART") || raw.contains("whart") {
            let end = raw.len().min(80);
            format!("HART-IP Advanced: {}", &raw[..end])
        } else {
            format!("HART-IP Advanced ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HartIpAdvanced,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hart_ip_advanced_data() {
        let buf = b"HART:IP:WirelessHART:pv=24.5:device=01";
        let r = dissect_hart_ip_advanced(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::HartIpAdvanced);
        assert!(r.summary.contains("HART-IP"));
    }

    #[test]
    fn test_hart_ip_advanced_malformed() {
        let buf = b"short";
        let r = dissect_hart_ip_advanced(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
