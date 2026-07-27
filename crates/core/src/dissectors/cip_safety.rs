use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cip_safety(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let msg_type = match payload[0] {
            0x01 => "SafeOpen",
            0x02 => "SafeClose",
            0x03 => "SafeOutput",
            0x04 => "SafeInput",
            0x05 => "SafeHeartbeat",
            0x06 => "SafeConfig",
            _ => "SafetyMsg",
        };
        let conn_id = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
        format!("CIP Safety — {} conn:0x{:08x} ({} bytes)", msg_type, conn_id, payload.len())
    } else {
        format!("CIP Safety — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CipSafety,
        summary,
    }
}
