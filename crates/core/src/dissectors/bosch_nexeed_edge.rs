use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_bosch_nexeed_edge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let stream_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let data_type = match payload[4] {
            0x01 => "SensorFusion",
            0x02 => "PredictiveMaintenance",
            0x03 => "QualityMetrics",
            0x04 => "EnergyMonitor",
            _ => "Custom",
        };
        let timestamp = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        format!(
            "Bosch Nexeed — stream:{stream_id:x} type:{data_type} ts:{timestamp} ({})",
            super::bytes(payload.len() as u64)
        )
    } else {
        format!("Bosch Nexeed — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BoschNexeedEdge,
        summary,
    }
}
