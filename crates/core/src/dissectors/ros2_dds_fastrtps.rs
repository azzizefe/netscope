use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ros2_dds_fastrtps(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "ROS2 Fast DDS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("RTPS") && (raw.contains("fast") || raw.contains("Fast")) {
            let end = raw.len().min(80);
            format!("ROS2 Fast DDS: {}", &raw[..end])
        } else if raw.contains("DDS") && raw.contains("participant") {
            let end = raw.len().min(80);
            format!("ROS2 Fast DDS: {}", &raw[..end])
        } else {
            format!("ROS2 Fast DDS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ros2DdsFastrtps,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ros2_fast_dds_discovery() {
        let buf = b"RTPS:Fast:DDS:participant:topic=/cmd_vel";
        let r = dissect_ros2_dds_fastrtps(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ros2DdsFastrtps);
        assert!(r.summary.contains("Fast DDS"));
    }

    #[test]
    fn test_ros2_fast_dds_malformed() {
        let buf = b"shortpkt";
        let r = dissect_ros2_dds_fastrtps(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
