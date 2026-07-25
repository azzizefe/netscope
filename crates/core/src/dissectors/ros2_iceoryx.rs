use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ros2_iceoryx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ROS2 Iceoryx (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("iceoryx") || raw.contains("Iceoryx") || raw.contains("IOX") {
            let end = raw.len().min(80);
            format!("ROS2 Iceoryx: {}", &raw[..end])
        } else if raw.contains("shm") && (raw.contains("topic") || raw.contains("publisher")) {
            let end = raw.len().min(80);
            format!("ROS2 Iceoryx: {}", &raw[..end])
        } else {
            format!("ROS2 Iceoryx ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ros2Iceoryx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ros2_iceoryx_chunk() {
        let buf = b"iceoryx:shm:/sensor/imu:seq=12";
        let r = dissect_ros2_iceoryx(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ros2Iceoryx);
        assert!(r.summary.contains("iceoryx"));
    }

    #[test]
    fn test_ros2_iceoryx_malformed() {
        let buf = b"shmdata";
        let r = dissect_ros2_iceoryx(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
