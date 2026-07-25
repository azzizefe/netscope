use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_rosbridge_websocket_v3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "rosbridge WebSocket v3 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("rosbridge") || raw.contains("ros_bridge") {
            let end = raw.len().min(80);
            format!("rosbridge WebSocket v3: {}", &raw[..end])
        } else if raw.contains("op:") && (raw.contains("topic:") || raw.contains("msg:")) {
            let end = raw.len().min(80);
            format!("rosbridge WebSocket v3: {}", &raw[..end])
        } else {
            format!("rosbridge WebSocket v3 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RosbridgeWebsocketV3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rosbridge_ws_v3_publish() {
        let buf = b"rosbridge:op:publish:topic:/cmd_vel:msg:linear";
        let r = dissect_rosbridge_websocket_v3(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::RosbridgeWebsocketV3);
        assert!(r.summary.contains("rosbridge"));
    }

    #[test]
    fn test_rosbridge_ws_v3_malformed() {
        let buf = b"short";
        let r = dissect_rosbridge_websocket_v3(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
