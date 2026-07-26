use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nxp_eiq_inference(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let backend = match payload[0] {
            0x01 => "NPU",
            0x02 => "DSP",
            0x03 => "CPU",
            0x04 => "GPU",
            _ => "Auto",
        };
        let status = match payload[1] {
            0x00 => "OK",
            0x01 => "Busy",
            0x02 => "Error",
            0x03 => "Timeout",
            _ => "Unknown",
        };
        let inference_id = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        format!("NXP eIQ — backend:{backend} status:{status} id:{inference_id} ({} bytes)", payload.len())
    } else {
        format!("NXP eIQ — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NxpEiqInference,
        summary,
    }
}
