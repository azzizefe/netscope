use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_intel_realsense_dds(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Intel RealSense DDS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("RealSense") || raw.contains("realsense") {
            let end = raw.len().min(80);
            format!("Intel RealSense DDS: {}", &raw[..end])
        } else if raw.contains("depth") || raw.contains("color") || raw.contains("imu") {
            format!("Intel RealSense DDS: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Intel RealSense DDS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IntelRealsenseDds,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_realsense_dds_stream() {
        let buf = b"RealSense:depth:color:imu_stream";
        let r = dissect_intel_realsense_dds(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IntelRealsenseDds);
        assert!(r.summary.contains("RealSense"));
    }

    #[test]
    fn test_intel_realsense_dds_malformed() {
        let buf = b"short";
        let r = dissect_intel_realsense_dds(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
