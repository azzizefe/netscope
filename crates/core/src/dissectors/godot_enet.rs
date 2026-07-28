use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_godot_enet(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Godot ENet (malformed)".into()
    } else {
        let flags = payload[0];
        let channel = payload[1];
        let seq = u16::from_be_bytes([payload[2], payload[3]]);
        let reliable = if flags & 0x80 != 0 { "R" } else { "U" };
        format!("Godot ENet {} ch{} seq{}", reliable, channel, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GodotEnet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_godot_enet_reliable() {
        let r = dissect_godot_enet(None, None, 9876, 9876, b"\x80\x00\x00\x01\xbe\xef");
        assert_eq!(r.protocol, Protocol::GodotEnet);
        assert!(r.summary.contains("R"));
    }

    #[test]
    fn test_godot_enet_unreliable() {
        let r = dissect_godot_enet(None, None, 9876, 9876, b"\x00\x01\x00\x02");
        assert_eq!(r.protocol, Protocol::GodotEnet);
        assert!(r.summary.contains("U"));
    }
}
