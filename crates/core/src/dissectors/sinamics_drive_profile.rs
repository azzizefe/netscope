use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_sinamics_drive_profile(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let stw = u16::from_be_bytes([payload[0], payload[1]]);
        let zsw = u16::from_be_bytes([payload[2], payload[3]]);
        let profile_ver = payload.get(4).copied().unwrap_or(0);

        let drive_class = match profile_ver >> 4 {
            1 => "Class 1 (speed)",
            2 => "Class 2 (technology)",
            3 => "Class 3 (positioning)",
            4 => "Class 4 (isochronous)",
            _ => "extended",
        };

        let stw_desc = if stw & 0x0001 != 0 { "ON" } else { "OFF" };
        let safety_limited = if stw & 0x0080 != 0 { " SLS" } else { "" };

        format!("SINAMICS Drive — Class {drive_class} Ctrl:0x{stw:04x} ({stw_desc}){safety_limited} Status:0x{zsw:04x} ({len} bytes)", len = payload.len())
    } else {
        format!("SINAMICS Drive Profile — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SinamicsDriveProfile,
        summary,
    }
}
