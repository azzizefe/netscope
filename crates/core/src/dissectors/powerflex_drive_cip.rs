use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_powerflex_drive_cip(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let instance = u16::from_be_bytes([payload[2], payload[3]]);
        let attribute = u16::from_be_bytes([payload[4], payload[5]]);
        let energy_val = u32::from_be_bytes([
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
            payload.get(8).copied().unwrap_or(0),
            payload.get(9).copied().unwrap_or(0),
        ]);

        let class_name = match class_id {
            0x4E => "Energy (0x4E)",
            0x04 => "Drive (0x04)",
            0x29 => "Motor (0x29)",
            0x2A => "Torque (0x2A)",
            _ => "",
        };

        let attr_name = match (class_id, attribute) {
            (0x4E, 0x03) => "TotalEnergy",
            (0x4E, 0x04) => "EnergyPeakDemand",
            (0x4E, 0x05) => "PowerFactor",
            (0x2A, 0x01) => "TorqueActual",
            (0x2A, 0x02) => "TorqueLimit",
            (0x29, 0x0C) => "MotorThermal",
            _ => "",
        };

        format!("PowerFlex CIP Drive — {class_name} inst:{instance} {attr_name} val:{energy_val} ({len} bytes)", len = payload.len())
    } else {
        format!("PowerFlex CIP Drive — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::PowerflexDriveCip,
        summary,
    }
}
