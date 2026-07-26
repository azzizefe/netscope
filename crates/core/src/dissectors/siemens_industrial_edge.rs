use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_siemens_industrial_edge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let app_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = match payload[4] {
            0x01 => "AppLifecycle",
            0x02 => "DataPipeline",
            0x03 => "OPCuaBridge",
            0x04 => "Heartbeat",
            0x05 => "ConfigSync",
            _ => "Data",
        };
        let seq = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        format!("Siemens Industrial Edge — app:{app_id:x} {msg_type} seq:{seq} ({} bytes)", payload.len())
    } else {
        format!("Siemens Industrial Edge — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SiemensIndustrialEdge,
        summary,
    }
}
