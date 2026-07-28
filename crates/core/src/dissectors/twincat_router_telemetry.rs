use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_twincat_router_telemetry(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let msg_type = payload[0];
        let task_id = payload.get(1).copied().unwrap_or(0);
        let cpu_load = payload.get(2).copied().unwrap_or(0);
        let cycle_time_us = u32::from_be_bytes([
            0,
            payload.get(3).copied().unwrap_or(0),
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);
        let jitter_ns = u32::from_be_bytes([
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
            payload.get(8).copied().unwrap_or(0),
            payload.get(9).copied().unwrap_or(0),
        ]);

        let type_name = match msg_type {
            0x01 => "TaskJitter",
            0x02 => "CycleExceed",
            0x03 => "CPULoad",
            0x04 => "CommLoad",
            0x05 => "RouterHeartbeat",
            _ => "Router msg",
        };

        let cycle_note = if cycle_time_us > 0 {
            format!(" cycle:{cycle_time_us}μs")
        } else {
            String::new()
        };

        format!("TwinCAT Router Telemetry — {type_name} task:{task_id}{cycle_note} jitter:{jitter_ns}ns cpu:{cpu_load}% ({len} bytes)", len = payload.len())
    } else {
        format!(
            "TwinCAT Router Telemetry — {len} bytes",
            len = payload.len()
        )
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::TwincatRouterTelemetry,
        summary,
    }
}
