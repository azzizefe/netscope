use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_basler_blaze_tof(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Basler Blaze ToF (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Basler") || raw.contains("blaze") || raw.contains("tof") {
            let end = raw.len().min(80);
            format!("Basler Blaze ToF: {}", &raw[..end])
        } else if raw.contains("depth_map") || raw.contains("point_cloud") {
            format!("Basler Blaze ToF: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Basler Blaze ToF ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BaslerBlazeTof,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basler_blaze_tof_stream() {
        let buf = b"Basler blaze:depth_map:1920x1080";
        let r = dissect_basler_blaze_tof(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::BaslerBlazeTof);
        assert!(r.summary.contains("Basler"));
    }

    #[test]
    fn test_basler_blaze_tof_malformed() {
        let buf = b"short";
        let r = dissect_basler_blaze_tof(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
