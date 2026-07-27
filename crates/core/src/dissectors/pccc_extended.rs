use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pccc_extended(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let dst_addr = payload[0];
        let src_addr = payload[1];
        let cmd = payload[2];
        let status = payload[3];

        let cmd_name = match cmd {
            0x00 => "ProtectedWrite",
            0x01 => "UnprotectedRead",
            0x02 => "UnprotectedWrite",
            0x03 => "ProtectedRead",
            0x05 => "BitWrite",
            0x06 => "DiagnosticStatus",
            0x0A => "FileRead",
            0x0B => "FileWrite",
            0x0C => "FileCopy",
            0x0D => "FileFill",
            0x21 => "DiagnosticCounters",
            0x4C => "SetSecurity",
            0x50 => "OnlineProgramChange",
            _ => "PCCC cmd",
        };

        let file_type = if cmd >= 0x0A && cmd <= 0x0D && payload.len() > 4 {
            Some(match payload[4] {
                0x00 => " (N-file)",
                0x01 => " (F-file)",
                0x02 => " (B-file)",
                0x07 => " (ST-file)",
                _ => "",
            })
        } else {
            None
        };

        let sts = if status != 0 { format!(" sts:0x{status:02x}") } else { String::new() };

        format!("PCCC (Extended) — {cmd_name}{src} dst:{dst_addr} src:{src_addr}{sts} ({len} bytes)", cmd_name = cmd_name, src = file_type.unwrap_or(""), len = payload.len())
    } else {
        format!("PCCC (Extended) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::PcccExtended,
        summary,
    }
}
