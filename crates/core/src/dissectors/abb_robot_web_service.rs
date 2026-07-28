use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_abb_robot_web_service(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let rw_version = payload[0];
        let msg_type = payload.get(1).copied().unwrap_or(0);
        let seq = u16::from_be_bytes([
            payload.get(2).copied().unwrap_or(0),
            payload.get(3).copied().unwrap_or(0),
        ]);

        let type_name = match msg_type {
            0x01 => "MotionData",
            0x02 => "ProgramUpload",
            0x03 => "ProgramDownload",
            0x04 => "IOSignal",
            0x05 => "RobotStatus",
            0x06 => "RAPIDvarRead",
            0x07 => "RAPIDvarWrite",
            0x08 => "FileTransfer",
            _ => "RW msg",
        };

        format!(
            "ABB Robot Web Services — {type_name} RW{v} seq:{seq} ({len} bytes)",
            v = rw_version,
            len = payload.len()
        )
    } else {
        format!("ABB Robot Web Services — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::AbbRobotWebService,
        summary,
    }
}
