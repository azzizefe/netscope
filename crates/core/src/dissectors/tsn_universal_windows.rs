use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tsn_universal_windows(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TSN Universal Windows (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TSN") || raw.contains("NIC_extension") || raw.contains("windows_tsn") {
            let end = raw.len().min(80);
            format!("TSN Universal Windows: {}", &raw[..end])
        } else if raw.contains("driver") || raw.contains("offload") || raw.contains("schedule") {
            format!("TSN Universal Windows: {}", &raw[..raw.len().min(80)])
        } else {
            format!("TSN Universal Windows ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TsnUniversalWindows,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_universal_windows_driver() {
        let buf = b"TSN:NIC_extension:driver_offload:schedule";
        let r = dissect_tsn_universal_windows(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TsnUniversalWindows);
        assert!(r.summary.contains("TSN"));
    }

    #[test]
    fn test_tsn_universal_windows_malformed() {
        let buf = b"short";
        let r = dissect_tsn_universal_windows(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
