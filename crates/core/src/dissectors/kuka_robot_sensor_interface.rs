use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_kuka_robot_sensor_interface(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let frame_type = payload[0];
        let seq = u32::from_be_bytes([payload.get(1).copied().unwrap_or(0), payload.get(2).copied().unwrap_or(0), payload.get(3).copied().unwrap_or(0), payload.get(4).copied().unwrap_or(0)]);
        let correction = i16::from_be_bytes([payload.get(5).copied().unwrap_or(0), payload.get(6).copied().unwrap_or(0)]);
        let sensor_id = payload.get(7).copied().unwrap_or(0);

        let type_name = match frame_type {
            0x01 => "CorrectionVector",
            0x02 => "ForceFeedback",
            0x03 => "PositionOverride",
            0x04 => "SensorConfig",
            0x05 => "Handshake",
            0x06 => "FrameStream",
            _ => "RSI frame",
        };

        let corr_str = if frame_type == 0x01 { format!(" corr:{correction}") } else { String::new() };

        format!("KUKA RSI — {type_name} seq:{seq}{corr_str} sensor:{sensor_id} ({len} bytes)", len = payload.len())
    } else {
        format!("KUKA RSI — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::KukaRobotSensorInterface,
        summary,
    }
}
