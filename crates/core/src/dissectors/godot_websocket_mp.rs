use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_godot_websocket_mp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        "Godot WebSocket MP (malformed)".into()
    } else {
        let opcode = payload[0];
        let peer_id = u16::from_be_bytes([payload[1], payload[2]]);
        let op_name = match opcode {
            0 => "Connect",
            1 => "Disconnect",
            2 => "Data",
            3 => "Ping",
            4 => "Pong",
            _ => "Unknown",
        };
        format!("Godot WebSocket MP {} peer {}", op_name, peer_id)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GodotWebsocketMp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_godot_websocket_mp_data() {
        let r = dissect_godot_websocket_mp(None, None, 9877, 9877, b"\x02\x00\x01\x48\x65\x6c\x6c\x6f");
        assert_eq!(r.protocol, Protocol::GodotWebsocketMp);
        assert!(r.summary.contains("Data"));
    }

    #[test]
    fn test_godot_websocket_mp_connect() {
        let r = dissect_godot_websocket_mp(None, None, 9877, 9878, b"\x00\x00\x00");
        assert_eq!(r.protocol, Protocol::GodotWebsocketMp);
        assert!(r.summary.contains("Connect"));
    }
}
