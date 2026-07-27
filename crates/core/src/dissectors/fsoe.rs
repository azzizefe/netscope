use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fsoe(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let cmd = match payload[0] {
            0x00 => "Reset",
            0x01 => "Start",
            0x02 => "Stop",
            0x03 => "Data",
            0x04 => "FailSafe",
            0x05 => "Heartbeat",
            _ => "Command",
        };
        let crc = u16::from_le_bytes([payload[4], payload[5]]);
        format!("FSoE — {} crc:0x{:04x} ({} bytes)", cmd, crc, payload.len())
    } else {
        format!("FSoE — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fsoe,
        summary,
    }
}
