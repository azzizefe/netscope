use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_varan_bus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let fc = match payload[0] {
            0x01 => "CyclicIO",
            0x02 => "Mailbox",
            0x03 => "Event",
            0x04 => "Configuration",
            0x05 => "Safety",
            0x06 => "Diagnostics",
            _ => "Data",
        };
        let len = u16::from_be_bytes([payload[4], payload[5]]);
        format!("VARAN Bus — {} len:{} ({} bytes)", fc, len, payload.len())
    } else {
        format!("VARAN Bus — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VaranBus,
        summary,
    }
}
