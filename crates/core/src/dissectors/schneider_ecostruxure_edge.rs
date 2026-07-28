use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// Whether this is an EcoStruxure Edge frame rather than something else on 8080.
///
/// 8080 is not assigned to Schneider — it is the HTTP alternate port, and the
/// gateway's own web UI shares it. Claiming the port outright labels every
/// ordinary request on it as EcoStruxure, so the framing has to agree first.
///
/// The message type at offset 4 is the check: the defined values are 0x01-0x05,
/// which are control characters. A text protocol cannot land one there — `GET `
/// puts `/` at offset 4 and `POST /` a space.
pub fn looks_like_schneider_ecostruxure_edge(payload: &[u8]) -> bool {
    payload.len() >= 16 && matches!(payload[4], 0x01..=0x05)
}

pub fn dissect_schneider_ecostruxure_edge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let asset_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = match payload[4] {
            0x01 => "Telemetry",
            0x02 => "AssetSync",
            0x03 => "Command",
            0x04 => "Config",
            0x05 => "Heartbeat",
            _ => "Data",
        };
        let seq = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let ts = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        format!(
            "EcoStruxure Edge — asset:{asset_id:x} {msg_type} seq:{seq} ts:{ts} ({})",
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("EcoStruxure Edge — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SchneiderEcostruxureEdge,
        summary,
    }
}
