use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_as_interface(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let cmd = match payload[0] {
            0x01 => "DataExchange",
            0x02 => "WriteParameter",
            0x03 => "ReadParameter",
            0x04 => "Identify",
            0x05 => "Status",
            0x06 => "SafetyMonitor",
            _ => "Command",
        };
        let slave = payload[1] & 0x1F;
        format!(
            "AS-Interface — {} slave:{} data:{:02x} ({})",
            cmd,
            slave,
            payload[4],
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("AS-Interface — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AsInterface,
        summary,
    }
}
