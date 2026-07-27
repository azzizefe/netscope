use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_controlnet(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let pkt_type = match payload[0] {
            0x01 => "Scheduled",
            0x02 => "Unscheduled",
            0x03 => "Maintenance",
            0x04 => "Redundancy",
            0x05 => "TimeSync",
            _ => "Data",
        };
        let slot = payload[1];
        format!("ControlNet — {} slot:{} ({} bytes)", pkt_type, slot, payload.len())
    } else {
        format!("ControlNet — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ControlNet,
        summary,
    }
}
