use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_steam_game_networking_s2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Steam GameNetworkingSockets v2 (malformed)".into()
    } else {
        let channel = payload[0];
        let msg_type = payload[1];
        let seq = u16::from_be_bytes([payload[2], payload[3]]);
        let conn = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let type_name = match msg_type {
            0 => "Unreliable",
            1 => "Reliable",
            2 => "Connect",
            3 => "Accept",
            4 => "Fin",
            5 => "Ping",
            _ => "Unknown",
        };
        format!("SteamNetS2 chan={} {} seq={} conn={}", channel, type_name, seq, conn)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SteamGameNetworkingS2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steam_net_s2_reliable() {
        let r = dissect_steam_game_networking_s2(None, None, 27015, 27015, b"\x00\x01\x00\x05\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::SteamGameNetworkingS2);
        assert!(r.summary.contains("Reliable"));
        assert!(r.summary.contains("seq=5"));
    }
}
