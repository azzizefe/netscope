use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethercat_distributed_clocks(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let dc_mode = payload[0];
        let cycle_us = u32::from_be_bytes([payload.get(1).copied().unwrap_or(0), payload.get(2).copied().unwrap_or(0), payload.get(3).copied().unwrap_or(0), payload.get(4).copied().unwrap_or(0)]);
        let shift_us = payload.get(5).copied().unwrap_or(0);
        let drift_ns = i16::from_be_bytes([payload.get(6).copied().unwrap_or(0), payload.get(7).copied().unwrap_or(0)]);

        let mode_name = match dc_mode {
            0x00 => "Free-run",
            0x01 => "SM-sync",
            0x02 => "DC-sync (input)",
            0x03 => "DC-sync (output)",
            _ => "DC mode",
        };

        let drift = if drift_ns != 0 {
            format!(" drift:{drift_ns:+}ns")
        } else {
            String::new()
        };

        format!("EtherCAT DC Sync — {mode_name} cycle:{cycle_us}μs shift:{shift_us}μs{drift} ({len} bytes)", len = payload.len())
    } else {
        format!("EtherCAT DC Sync — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::EthercatDistributedClocks,
        summary,
    }
}
