use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_psn_matchmaking_v3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PSN Matchmaking v3 (malformed)".into()
    } else {
        let _magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = payload[4];
        let version = payload[5];
        let seq = u16::from_be_bytes([payload[6], payload[7]]);
        let type_name = match msg_type {
            0x01 => "FindSession",
            0x02 => "FindSessionResponse",
            0x03 => "CreateSession",
            0x04 => "JoinSession",
            0x05 => "LeaveSession",
            0x06 => "KeepAlive",
            _ => "Unknown",
        };
        format!("PSN MMv3 {} v{} seq={}", type_name, version, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PsnMatchmakingV3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psn_mm_find() {
        let r = dissect_psn_matchmaking_v3(None, None, 9302, 9302, b"\x00\x00\x00\x01\x01\x01\x00\x01");
        assert_eq!(r.protocol, Protocol::PsnMatchmakingV3);
        assert!(r.summary.contains("FindSession"));
    }
}
