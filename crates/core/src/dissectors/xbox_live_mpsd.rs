use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_xbox_live_mpsd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Xbox Live MPSD (malformed)".into()
    } else {
        let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
        let session_id = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let flags = u16::from_be_bytes([payload[6], payload[7]]);
        let type_name = match msg_type {
            0x0101 => "CreateSession",
            0x0102 => "JoinSession",
            0x0103 => "LeaveSession",
            0x0104 => "QuerySession",
            0x0105 => "UpdateSession",
            0x0201 => "SessionData",
            0x0202 => "MemberJoin",
            0x0203 => "MemberLeave",
            _ => "Unknown",
        };
        format!(
            "Xbox MPSD {} session={} flags=0x{:04x}",
            type_name, session_id, flags
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XboxLiveMpsd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xbox_mpsd_create() {
        let r = dissect_xbox_live_mpsd(None, None, 3074, 3074, b"\x01\x01\x00\x00\x00\x01\x00\x00");
        assert_eq!(r.protocol, Protocol::XboxLiveMpsd);
        assert!(r.summary.contains("CreateSession"));
    }
}
