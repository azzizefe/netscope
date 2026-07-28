use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_bosch_rexroth_open_core(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let oci_version = payload[0];
        let msg_type = payload.get(1).copied().unwrap_or(0);
        let session = u32::from_be_bytes([
            payload.get(2).copied().unwrap_or(0),
            payload.get(3).copied().unwrap_or(0),
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);
        let cmd = u16::from_be_bytes([
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
        ]);

        let type_name = match msg_type {
            0x01 => "AppBridge",
            0x02 => "PLCvarAccess",
            0x03 => "IEC61131Data",
            0x04 => "IIoTTelemetry",
            0x05 => "AlarmEvent",
            0x06 => "ConfigTransfer",
            _ => "OCI msg",
        };

        let cmd_name = match cmd {
            0x0101 => "ReadVariable",
            0x0102 => "WriteVariable",
            0x0103 => "SubscribeVariable",
            0x0104 => "UnsubscribeVariable",
            0x0201 => "TaskControl",
            0x0202 => "DeviceInfo",
            0x0301 => "CloudPublish",
            _ => "OCI cmd",
        };

        format!("Rexroth Open Core — {type_name} {cmd_name} v{ver} session:0x{session:08x} ({len} bytes)", ver = oci_version, len = payload.len())
    } else {
        format!("Rexroth Open Core — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::BoschRexrothOpenCore,
        summary,
    }
}
