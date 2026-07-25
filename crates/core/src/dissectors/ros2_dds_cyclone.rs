use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ros2_dds_cyclone(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ROS2 Cyclone DDS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Cyclone") || raw.contains("cyclone") || raw.contains("Iceoryx") {
            let end = raw.len().min(80);
            format!("ROS2 Cyclone DDS: {}", &raw[..end])
        } else if raw.contains("DDS") && (raw.contains("shared") || raw.contains("shm")) {
            let end = raw.len().min(80);
            format!("ROS2 Cyclone DDS: {}", &raw[..end])
        } else {
            format!("ROS2 Cyclone DDS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ros2DdsCyclone,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ros2_cyclone_dds_pub() {
        let buf = b"Cyclone:shm:/scan:iceoryx:seq=5";
        let r = dissect_ros2_dds_cyclone(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ros2DdsCyclone);
        assert!(r.summary.contains("Cyclone"));
    }

    #[test]
    fn test_ros2_cyclone_dds_malformed() {
        let buf = b"tiny";
        let r = dissect_ros2_dds_cyclone(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
