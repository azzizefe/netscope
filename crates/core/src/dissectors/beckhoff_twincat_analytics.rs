use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_beckhoff_twincat_analytics(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let channel = u16::from_le_bytes([payload[0], payload[1]]);
        let mode = match payload[2] {
            0x01 => "Cyclic",
            0x02 => "EventTriggered",
            0x03 => "Diagnostic",
            0x04 => "CloudForward",
            _ => "Raw",
        };
        let sample_count = u16::from_le_bytes([payload[4], payload[5]]);
        let cycle_counter = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        format!("TwinCAT Analytics — ch:{channel} {mode} samples:{sample_count} cycle:{cycle_counter} ({})", super::bytes(payload.len() as u64))
    } else {
        format!("TwinCAT Analytics — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BeckhoffTwincatAnalytics,
        summary,
    }
}
