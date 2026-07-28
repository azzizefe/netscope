use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

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
        format!(
            "CIP Safety — {} conn:0x{:08x} ({})",
            msg_type,
            conn_id,
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("CIP Safety — {}", super::bytes(payload.len() as u64))
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
