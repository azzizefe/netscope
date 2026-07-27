use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_profidrive(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let svc = match payload[0] {
            0x01 => "Setpoint",
            0x02 => "ActualValue",
            0x03 => "ParameterRead",
            0x04 => "ParameterWrite",
            0x05 => "Diagnosis",
            0x06 => "ControlWord",
            0x07 => "StatusWord",
            _ => "Service",
        };
        let drive = payload[1];
        format!("PROFIdrive — {} drive:{} ({})", svc, drive, super::bytes(payload.len() as u64))
    } else {
        format!("PROFIdrive — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Profidrive,
        summary,
    }
}
