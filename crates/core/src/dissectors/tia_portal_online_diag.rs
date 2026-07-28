use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_tia_portal_online_diag(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let msg_type = payload[0];
        let slot = payload.get(1).copied().unwrap_or(0);
        let rack = payload.get(2).copied().unwrap_or(0);
        let sequence = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let type_name = match msg_type {
            0x01 => "ModuleStatus",
            0x02 => "TopologyQuery",
            0x03 => "FirmwareInventory",
            0x04 => "DiagnosticBuffer",
            0x05 => "UpdateTrigger",
            0x06 => "StationInfo",
            0x07 => "Identification",
            _ => "Diag",
        };

        format!(
            "TIA Portal Diag — {type_name} rack:{rack} slot:{slot} seq:{sequence} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("TIA Portal Online Diag — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::TiaPortalOnlineDiag,
        summary,
    }
}
