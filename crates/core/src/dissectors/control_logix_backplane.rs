use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_control_logix_backplane(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let slot_src = payload[0];
        let slot_dst = payload[1];
        let msg_type = payload.get(2).copied().unwrap_or(0);
        let chassis_id = payload.get(3).copied().unwrap_or(0);
        let seq = u16::from_be_bytes([payload.get(4).copied().unwrap_or(0), payload.get(5).copied().unwrap_or(0)]);

        let type_name = match msg_type {
            0x01 => "OwnerTransfer",
            0x02 => "RedundantSync",
            0x03 => "ModuleHealth",
            0x04 => "ChassisEnum",
            0x05 => "ConfigSync",
            0x06 => "FaultEvent",
            _ => "Backplane msg",
        };

        let owner_mode = if msg_type == 0x01 && payload.len() > 6 {
            match payload[6] {
                0x00 => " (become owner)",
                0x01 => " (release ownership)",
                _ => "",
            }
        } else {
            ""
        };

        format!("ControlLogix Backplane — {type_name}{owner_mode} slot:{slot_src}→{slot_dst} chassis:{chassis_id} seq:{seq} ({len} bytes)", len = payload.len())
    } else {
        format!("ControlLogix Backplane — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::ControlLogixBackplane,
        summary,
    }
}
