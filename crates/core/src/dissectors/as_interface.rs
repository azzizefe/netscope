use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

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
        format!("AS-Interface — {} slave:{} data:{:02x} ({} bytes)", cmd, slave, payload[4], payload.len())
    } else {
        format!("AS-Interface — {} bytes", payload.len())
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
