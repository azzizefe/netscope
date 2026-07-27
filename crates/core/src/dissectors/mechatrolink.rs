use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mechatrolink(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let cmd = match payload[0] {
            0x01 => "Position",
            0x02 => "Velocity",
            0x03 => "Torque",
            0x04 => "Interpolation",
            0x05 => "Homing",
            0x06 => "ReadParameter",
            0x07 => "WriteParameter",
            0x08 => "Status",
            0x09 => "Synchronous",
            _ => "Command",
        };
        let axis = payload[1];
        format!("MECHATROLINK — {} axis:{} seq:{} ({})", cmd, axis, payload[2], super::bytes(payload.len() as u64))
    } else {
        format!("MECHATROLINK — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mechatrolink,
        summary,
    }
}
