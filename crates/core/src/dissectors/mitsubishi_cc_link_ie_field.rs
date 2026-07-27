use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mitsubishi_cc_link_ie_field(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let data_type = payload[0];
        let station = payload.get(1).copied().unwrap_or(0);
        let cpu_slot = payload.get(2).copied().unwrap_or(0);
        let seq = u16::from_be_bytes([payload.get(4).copied().unwrap_or(0), payload.get(5).copied().unwrap_or(0)]);

        let type_name = match data_type {
            0x01 => "Cyclic data",
            0x02 => "Transient data",
            0x03 => "Motion parameter",
            0x04 => "Servo config",
            0x05 => "Network variable",
            0x06 => "Shared memory",
            _ => "CC-Link IE frame",
        };

        format!("CC-Link IE Field (Ext) — {type_name} station:{station} cpu:{cpu_slot} seq:{seq} ({len} bytes)", len = payload.len())
    } else {
        format!("CC-Link IE Field (Ext) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MitsubishiCcLinkIeField,
        summary,
    }
}
