use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_siemens_l2_telegram(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let service = payload[0];
        let block_type = payload.get(2).copied().unwrap_or(0);

        let service_name = match service {
            0x03 => "Get",
            0x04 => "Set",
            0x05 => "Identify",
            0x06 => "Hello",
            0xFF => "Factory Reset",
            _ => "Service",
        };

        let block_name = match block_type {
            0x01 => "IP parameter",
            0x02 => "NameOfStation",
            0x03 => "DeviceVendor",
            0x04 => "DeviceID",
            0x05 => "DeviceRole",
            0x06 => "DeviceOptions",
            0x07 => "RTClass",
            _ => "Block",
        };

        format!(
            "PROFINET DCP (Siemens L2) — {service_name} {block_name} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!(
            "PROFINET DCP (Siemens L2) — {len} bytes",
            len = payload.len()
        )
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SiemensL2Telegram,
        summary,
    }
}
