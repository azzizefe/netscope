use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_micro_ros_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "micro-ROS UDP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("micro-ros") && raw.contains("UDP") {
            let end = raw.len().min(80);
            format!("micro-ROS UDP: {}", &raw[..end])
        } else if raw.contains("XRCE") && (raw.contains("transport") || raw.contains("stream")) {
            let end = raw.len().min(80);
            format!("micro-ROS UDP: {}", &raw[..end])
        } else {
            format!("micro-ROS UDP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MicroRosUdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_ros_udp_stream() {
        let buf = b"micro-ros:UDP:XRCE:stream:seq=7";
        let r = dissect_micro_ros_udp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MicroRosUdp);
        assert!(r.summary.contains("micro-ROS"));
    }

    #[test]
    fn test_micro_ros_udp_malformed() {
        let buf = b"tiny";
        let r = dissect_micro_ros_udp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
