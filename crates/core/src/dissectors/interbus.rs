use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_interbus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 10 {
        let fc = match payload[0] {
            0x10 => "ProcessData",
            0x11 => "ParameterChannel",
            0x12 => "Diagnostics",
            0x13 => "Identification",
            0x14 => "Configuration",
            0x20 => "TCP/IP Encapsulation",
            _ => "Data",
        };
        let len = u16::from_be_bytes([payload[2], payload[3]]);
        format!(
            "INTERBUS — {} len:{} ({})",
            fc,
            len,
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("INTERBUS — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Interbus,
        summary,
    }
}
