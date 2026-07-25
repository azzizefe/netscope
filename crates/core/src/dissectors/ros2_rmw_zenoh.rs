use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ros2_rmw_zenoh(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "ROS2 rmw_zenoh (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("rmw_zenoh") || raw.contains("zenoh") && raw.contains("ros") {
            let end = raw.len().min(80);
            format!("ROS2 rmw_zenoh: {}", &raw[..end])
        } else if raw.contains("/ros/") || raw.contains("/rcl/") {
            let end = raw.len().min(80);
            format!("ROS2 rmw_zenoh: {}", &raw[..end])
        } else {
            format!("ROS2 rmw_zenoh ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ros2RmwZenoh,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ros2_rmw_zenoh_sub() {
        let buf = b"rmw_zenoh:/ros/topic:/odom:pub=5";
        let r = dissect_ros2_rmw_zenoh(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ros2RmwZenoh);
        assert!(r.summary.contains("zenoh"));
    }

    #[test]
    fn test_ros2_rmw_zenoh_malformed() {
        let buf = b"abcde";
        let r = dissect_ros2_rmw_zenoh(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
