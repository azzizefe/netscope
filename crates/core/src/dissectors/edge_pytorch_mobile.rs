use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_edge_pytorch_mobile(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let version = u16::from_le_bytes([payload[0], payload[1]]);
        let method = match payload[2] {
            0x01 => "Forward",
            0x02 => "LoadModel",
            0x03 => "RunMethod",
            0x04 => "GetInputs",
            _ => "Unknown",
        };
        let tensor_count = u16::from_le_bytes([payload[4], payload[5]]);
        format!(
            "PyTorch Mobile — v{version} {method} tensors:{tensor_count} ({})",
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("PyTorch Mobile — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EdgePytorchMobile,
        summary,
    }
}
