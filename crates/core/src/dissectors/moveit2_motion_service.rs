use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_moveit2_motion_service(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "MoveIt2 Motion Service (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("MoveIt2") || raw.contains("moveit") && raw.contains("motion") {
            let end = raw.len().min(80);
            format!("MoveIt2 Motion Service: {}", &raw[..end])
        } else if raw.contains("planning") && raw.contains("trajectory") {
            let end = raw.len().min(80);
            format!("MoveIt2 Motion Service: {}", &raw[..end])
        } else {
            format!("MoveIt2 Motion Service ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Moveit2MotionService,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moveit2_motion_plan() {
        let buf = b"MoveIt2:motion:planning:trajectory:arm=6dof";
        let r = dissect_moveit2_motion_service(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Moveit2MotionService);
        assert!(r.summary.contains("MoveIt2"));
    }

    #[test]
    fn test_moveit2_motion_malformed() {
        let buf = b"short";
        let r = dissect_moveit2_motion_service(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
