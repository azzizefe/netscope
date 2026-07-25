use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_recroom_room_server(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Rec Room Room Server (malformed)".into()
    } else {
        let opcode = payload[0];
        let room_id = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let player_count = payload[4];
        format!(
            "Rec Room Room Server op=0x{:02x} room={} players={}",
            opcode, room_id, player_count
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RecroomRoomServer,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recroom_room_server_basic() {
        let buf = vec![0x01, 0x00, 0x05, 0x08, 0x0A];
        let r = dissect_recroom_room_server(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::RecroomRoomServer);
    }

    #[test]
    fn test_recroom_room_server_malformed() {
        let buf = vec![0x01, 0x00];
        let r = dissect_recroom_room_server(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
