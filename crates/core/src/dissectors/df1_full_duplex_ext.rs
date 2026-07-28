use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_df1_full_duplex_ext(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let dst_addr = payload[0];
        let src_addr = payload[1];
        let cmd = payload[2];
        let mode = payload.get(3).copied().unwrap_or(0);
        let seq = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let cmd_name = match cmd {
            0x00 => "Data",
            0x01 => "Ack",
            0x03 => "Nak",
            0x06 => "Enquiry",
            0x0F => "ProgUpload",
            0x10 => "ProgDownload",
            _ => "DF1 cmd",
        };

        let ext_mode = match mode & 0x03 {
            0x00 => "BCC",
            0x01 => "CRC-16",
            0x02 => "CRC-32",
            _ => "Unknown",
        };

        format!("DF1 Full-Duplex (Extended) — {cmd_name} dst:{dst_addr} src:{src_addr} mode:{ext_mode} seq:{seq} ({len} bytes)", len = payload.len())
    } else {
        format!(
            "DF1 Full-Duplex (Extended) — {len} bytes",
            len = payload.len()
        )
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::Df1FullDuplexExt,
        summary,
    }
}
