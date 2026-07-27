use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethercat_safety_beckhoff(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let fsoe_conn = u16::from_be_bytes([payload[0], payload[1]]);
        let seq_no = u16::from_be_bytes([payload[2], payload[3]]);
        let crc = u16::from_be_bytes([payload[4], payload[5]]);
        let cmd = payload.get(6).copied().unwrap_or(0);
        let safe_group = payload.get(7).copied().unwrap_or(0);

        let cmd_name = match cmd {
            0x01 => "Start",
            0x02 => "Data",
            0x03 => "Stop",
            0x04 => "FailSafe",
            _ => "FSoE cmd",
        };

        let beckhoff_ext = if safe_group > 0 {
            format!(" group:{safe_group}")
        } else {
            String::new()
        };

        format!("TwinSAFE (Beckhoff) — {cmd_name} conn:{fsoe_conn} seq:{seq_no} CRC:0x{crc:04x}{beckhoff_ext} ({len} bytes)", len = payload.len())
    } else {
        format!("TwinSAFE (Beckhoff) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::EthercatSafetyBeckhoff,
        summary,
    }
}
