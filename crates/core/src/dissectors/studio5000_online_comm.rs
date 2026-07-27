use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_studio5000_online_comm(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let session = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = payload.get(4).copied().unwrap_or(0);
        let sub_type = payload.get(5).copied().unwrap_or(0);
        let seq_no = u16::from_be_bytes([payload.get(6).copied().unwrap_or(0), payload.get(7).copied().unwrap_or(0)]);

        let type_name = match msg_type {
            0x01 => "TagBrowser",
            0x02 => "TagRead",
            0x03 => "TagWrite",
            0x04 => "CrossReference",
            0x05 => "OnlineRungEdit",
            0x06 => "ProgramUpload",
            0x07 => "ProgramDownload",
            0x08 => "TaskSync",
            0x09 => "ControllerSync",
            _ => "OnlineMsg",
        };

        let sub_name = match (msg_type, sub_type) {
            (0x05, 0x01) => " (insert rung)",
            (0x05, 0x02) => " (replace rung)",
            (0x05, 0x03) => " (delete rung)",
            (0x01, 0x01) => " (all tags)",
            (0x01, 0x02) => " (program-scoped)",
            _ => "",
        };

        format!("Studio 5000 Online — {type_name}{sub_name} session:0x{session:08x} seq:{seq_no} ({len} bytes)", len = payload.len())
    } else {
        format!("Studio 5000 Online — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::Studio5000OnlineComm,
        summary,
    }
}
