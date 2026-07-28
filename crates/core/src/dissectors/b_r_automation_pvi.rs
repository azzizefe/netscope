use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_br_automation_pvi(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let pvi_cmd = u16::from_be_bytes([payload[0], payload[1]]);
        let session = u16::from_be_bytes([payload[2], payload[3]]);
        let status = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let cmd_name = match pvi_cmd {
            0x0001 => "PVRead",
            0x0002 => "PVWrite",
            0x0003 => "PVSubscribe",
            0x0004 => "PVUnsubscribe",
            0x0005 => "PVNotification",
            0x0010 => "DeviceEnum",
            0x0011 => "AlarmSubscribe",
            0x0012 => "AlarmNotification",
            0x0013 => "DeviceInfo",
            _ => "PVI cmd",
        };

        format!(
            "B&R Automation PVI — {cmd_name} session:{session} status:{status} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("B&R Automation PVI — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::BrAutomationPvi,
        summary,
    }
}
