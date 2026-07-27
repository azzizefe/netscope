use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_edge_inference_onnx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let model_len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        let op = match payload[0] {
            0x01 => "SessionCreate",
            0x02 => "RunInference",
            0x03 => "GetOutput",
            0x04 => "ReleaseSession",
            _ => "UnknownOp",
        };
        let model = if model_len > 0 && model_len < 64 {
            String::from_utf8_lossy(&payload[8..8 + model_len.min(payload.len().saturating_sub(8))])
        } else {
            "".into()
        };
        if model.is_empty() {
            format!("ONNX Edge — {op} ({})", super::bytes(payload.len() as u64))
        } else {
            format!("ONNX Edge — {op} model:{model} ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("ONNX Edge — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EdgeInferenceOnnx,
        summary,
    }
}
