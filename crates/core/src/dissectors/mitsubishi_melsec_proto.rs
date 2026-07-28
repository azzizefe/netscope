use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_mitsubishi_melsec_proto(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let subheader = u16::from_be_bytes([payload[0], payload[1]]);
        let req_type = payload.get(2).copied().unwrap_or(0);
        let cmd = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let is_binary = subheader == 0x5000;
        let fmt = if is_binary { "Binary" } else { "ASCII" };

        let cmd_name = match cmd {
            0x0401 => "Read",
            0x1401 => "Write",
            0x0402 => "RandomRead",
            0x1402 => "RandomWrite",
            0x0403 => "ReadRandomBlock",
            0x1901 => "ReadBuffer",
            0x1A01 => "WriteBuffer",
            0x0101 => "ReadTypeName",
            0x0501 => "RemoteRun",
            0x0502 => "RemoteStop",
            0x0503 => "RemotePause",
            0x0601 => "PLCStatus",
            0x0D01 => "LabelAccess",
            0x0E01 => "IntelligentBufferRead",
            _ => "MC cmd",
        };

        let frame = if req_type == 0x00 {
            "Request"
        } else {
            "Response"
        };

        format!(
            "MELSEC MC Protocol ({fmt}) — {cmd_name} {frame} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("MELSEC MC Protocol — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MitsubishiMelsecProto,
        summary,
    }
}
