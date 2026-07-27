use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_edge_tensorflow_lite(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let op = match payload[0] {
            0x10 => "Invoke",
            0x11 => "GetStatus",
            0x12 => "SetTensor",
            0x13 => "GetTensor",
            0x14 => "Reset",
            _ => "Unknown",
        };
        let arena_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        format!("TFLite Micro — {op} arena:{arena_size}B ({})", super::bytes(payload.len() as u64))
    } else {
        format!("TFLite Micro — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EdgeTensorflowLite,
        summary,
    }
}
