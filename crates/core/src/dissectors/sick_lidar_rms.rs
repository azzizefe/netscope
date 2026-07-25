use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_sick_lidar_rms(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "SICK LiDAR RMS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SICK") || raw.contains("sick") || raw.contains("LiDAR") {
            let end = raw.len().min(80);
            format!("SICK LiDAR RMS: {}", &raw[..end])
        } else if raw.contains("scan_data") || raw.contains("rms_status") {
            format!("SICK LiDAR RMS: {}", &raw[..raw.len().min(80)])
        } else {
            format!("SICK LiDAR RMS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SickLidarRms,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sick_lidar_rms_scan() {
        let buf = b"SICK LiDAR:scan_data:rms_status=ok";
        let r = dissect_sick_lidar_rms(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SickLidarRms);
        assert!(r.summary.contains("SICK"));
    }

    #[test]
    fn test_sick_lidar_rms_malformed() {
        let buf = b"short";
        let r = dissect_sick_lidar_rms(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
