use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_sinumerik_nck_channel(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let channel = payload[0];
        let block_type = payload.get(1).copied().unwrap_or(0);
        let seq_no = u16::from_be_bytes([
            payload.get(2).copied().unwrap_or(0),
            payload.get(3).copied().unwrap_or(0),
        ]);
        let axis_bits = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let block_name = match block_type {
            0x01 => "G-Code block",
            0x02 => "Tool offset",
            0x03 => "Axis pos setpoint",
            0x04 => "Axis actual value",
            0x05 => "Tool change",
            0x06 => "Magazine assign",
            0x07 => "MDI command",
            0x08 => "Channel status",
            _ => "NCK frame",
        };

        let axis_count = axis_bits.count_ones();

        format!("SINUMERIK NCK — ch:{channel} {block_name} seq:{seq_no} axes:{axis_count} ({len} bytes)", len = payload.len())
    } else {
        format!("SINUMERIK NCK Channel — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SinumerikNckChannel,
        summary,
    }
}
