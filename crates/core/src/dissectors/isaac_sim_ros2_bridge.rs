use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_isaac_sim_ros2_bridge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Isaac Sim ROS2 Bridge (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Isaac") && (raw.contains("ROS2") || raw.contains("ros2")) {
            let end = raw.len().min(80);
            format!("Isaac Sim ROS2 Bridge: {}", &raw[..end])
        } else if raw.contains("simulation") && raw.contains("bridge") {
            let end = raw.len().min(80);
            format!("Isaac Sim ROS2 Bridge: {}", &raw[..end])
        } else {
            format!("Isaac Sim ROS2 Bridge ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IsaacSimRos2Bridge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isaac_sim_bridge() {
        let buf = b"Isaac:ROS2:bridge:simulation:scene=/warehouse";
        let r = dissect_isaac_sim_ros2_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IsaacSimRos2Bridge);
        assert!(r.summary.contains("Isaac"));
    }

    #[test]
    fn test_isaac_sim_bridge_malformed() {
        let buf = b"short";
        let r = dissect_isaac_sim_ros2_bridge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
