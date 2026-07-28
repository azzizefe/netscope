use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_keyence_kv_ethernet(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let cmd = payload[0];
        let unit = payload.get(1).copied().unwrap_or(0);
        let data_type = payload.get(2).copied().unwrap_or(0);
        let size = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let cmd_name = match cmd {
            0x01 => "DeviceRead",
            0x02 => "DeviceWrite",
            0x03 => "ProgramRead",
            0x04 => "ProgramWrite",
            0x05 => "RunControl",
            0x06 => "StatusRead",
            0x10 => "VisionTrigger",
            0x11 => "VisionResult",
            0x12 => "VisionConfig",
            _ => "KV cmd",
        };

        let unit_name = match unit {
            0x00 => "CPU",
            0x01 => "Ladder",
            0x02 => "Vision",
            _ => "",
        };

        format!("Keyence KV Ethernet — {cmd_name} {unit_name} type:{data_type} size:{size} ({len} bytes)", len = payload.len())
    } else {
        format!("Keyence KV Ethernet — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::KeyenceKvEthernet,
        summary,
    }
}
