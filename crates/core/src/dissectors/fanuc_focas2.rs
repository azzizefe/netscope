use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_fanuc_focas2(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let func = payload[0];
        let sub_func = payload.get(1).copied().unwrap_or(0);
        let data_type = u16::from_be_bytes([
            payload.get(2).copied().unwrap_or(0),
            payload.get(3).copied().unwrap_or(0),
        ]);
        let length = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let func_name = match (func, sub_func) {
            (0x01, _) => "CNCStatus",
            (0x02, _) => "AxisData",
            (0x03, _) => "SpindleData",
            (0x04, _) => "ServoTuning",
            (0x05, _) => "ToolOffset",
            (0x06, _) => "MacroVar",
            (0x07, _) => "AlarmHistory",
            (0x08, _) => "PMCRead",
            (0x09, _) => "PMCWrite",
            (0x0A, _) => "Diagnosis",
            (0x0B, _) => "ParamRead",
            (0x0C, _) => "ParamWrite",
            (0x0D, _) => "ProgramData",
            (0x10, 0x01) => "CNCFileRead",
            (0x10, 0x02) => "CNCFileWrite",
            _ => "FOCAS2 func",
        };

        format!("FANUC FOCAS2 — {func_name} sub:0x{sub_func:02x} type:0x{data_type:04x} len:{length} ({len} bytes)", len = payload.len())
    } else {
        format!("FANUC FOCAS2 — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::FanucFocas2,
        summary,
    }
}
