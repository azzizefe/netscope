use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_rockwell_factorytalk_edge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let session = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let op = match payload[4] {
            0x01 => "PublishTags",
            0x02 => "AlarmEvent",
            0x03 => "TunnelConnect",
            0x04 => "TunnelData",
            0x05 => "Heartbeat",
            0x06 => "ConfigSync",
            _ => "Data",
        };
        let tag_count = u16::from_le_bytes([payload[8], payload[9]]);
        format!(
            "FactoryTalk Edge — session:{session:x} {op} tags:{tag_count} ({})",
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("FactoryTalk Edge — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RockwellFactorytalkEdge,
        summary,
    }
}
