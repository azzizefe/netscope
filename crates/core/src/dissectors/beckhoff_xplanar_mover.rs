use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_beckhoff_xplanar_mover(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let mover_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let cmd = payload.get(4).copied().unwrap_or(0);
        let pos_x = i16::from_be_bytes([payload.get(5).copied().unwrap_or(0), payload.get(6).copied().unwrap_or(0)]);
        let pos_y = i16::from_be_bytes([payload.get(7).copied().unwrap_or(0), payload.get(8).copied().unwrap_or(0)]);
        let tilt_a = payload.get(9).copied().unwrap_or(0) as i8;
        let collision_domain = payload.get(10).copied().unwrap_or(0);

        let cmd_name = match cmd {
            0x01 => "PositionSetpoint",
            0x02 => "PositionActual",
            0x03 => "TrajectoryPlan",
            0x04 => "CollisionAvoid",
            0x05 => "EmergencyStop",
            0x06 => "MoverStatus",
            _ => "Mover cmd",
        };

        format!("XPlanar Mover — {cmd_name} id:{mover_id} X:{pos_x} Y:{pos_y} tilt:{tilt_a}° domain:{collision_domain} ({len} bytes)", len = payload.len())
    } else {
        format!("XPlanar Mover — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::BeckhoffXplanarMover,
        summary,
    }
}
