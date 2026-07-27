use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_s7comm_plus_detail(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let protocol_id = payload[0];
        let opcode = payload.get(1).copied().unwrap_or(0);
        let session = u16::from_be_bytes([payload.get(2).copied().unwrap_or(0), payload.get(3).copied().unwrap_or(0)]);
        let job_id = u16::from_be_bytes([payload.get(6).copied().unwrap_or(0), payload.get(7).copied().unwrap_or(0)]);

        let op_name = match opcode {
            0x01 => "Job",
            0x02 => "Ack",
            0x03 => "AckData",
            0x07 => "UserData",
            0x72 => "S7onTIA",
            _ => "Op",
        };

        let proto_info = if protocol_id == 0x72 {
            "S7Comm+ (v4.0+)"
        } else if protocol_id == 0x32 {
            "S7Comm+ (v3.x)"
        } else {
            "S7Comm+"
        };

        format!("{proto_info} — {op_name} session:{session} jobId:{job_id} ({len} bytes)", len = payload.len())
    } else {
        format!("S7Comm+ Detail — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::S7commPlusDetail,
        summary,
    }
}
