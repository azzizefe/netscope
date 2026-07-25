use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_micro_ros_serial(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "micro-ROS Serial (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("XRCE") || raw.contains("xrce") || raw.contains("micro-ros") {
            let end = raw.len().min(80);
            format!("micro-ROS Serial: {}", &raw[..end])
        } else if raw.contains("serial") && raw.contains("Agent") {
            let end = raw.len().min(80);
            format!("micro-ROS Serial: {}", &raw[..end])
        } else {
            format!("micro-ROS Serial ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MicroRosSerial,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_micro_ros_serial_frame() {
        let buf = b"XRCE:micro-ros:Agent:topic=/led";
        let r = dissect_micro_ros_serial(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MicroRosSerial);
        assert!(r.summary.contains("micro-ROS"));
    }

    #[test]
    fn test_micro_ros_serial_malformed() {
        let buf = b"smol";
        let r = dissect_micro_ros_serial(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
