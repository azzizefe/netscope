use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_playfab_multiplayer_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "PlayFab Multiplayer v2 (malformed)".into()
    } else {
        let opcode = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        let session_id = u32::from_be_bytes(payload[2..6].try_into().unwrap());
        let op_name = match opcode {
            0x0001 => "Allocate",
            0x0002 => "Heartbeat",
            0x0003 => "Shutdown",
            0x0004 => "PlayerJoin",
            0x0005 => "PlayerLeave",
            _ => "Unknown",
        };
        format!(
            "PlayFab Multiplayer v2 op={} session=0x{:08x}",
            op_name, session_id
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PlayfabMultiplayerV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playfab_multiplayer_v2_allocate() {
        let buf = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_playfab_multiplayer_v2(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PlayfabMultiplayerV2);
        assert!(r.summary.contains("Allocate"));
    }

    #[test]
    fn test_playfab_multiplayer_v2_malformed() {
        let buf = vec![0x00, 0x01, 0x00];
        let r = dissect_playfab_multiplayer_v2(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
