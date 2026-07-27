use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iolink(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let pdu_type = match payload[0] >> 4 {
            0x0 => "ProcessData",
            0x1 => "OnRequest",
            0x2 => "Event",
            0x3 => "ISDU",
            0x4 => "DeviceDiagnosis",
            _ => "Unknown",
        };
        let status = match payload[2] & 0x03 {
            0 => "OK",
            1 => "Invalid",
            2 => "NotSupported",
            3 => "Error",
            _ => "Unknown",
        };
        format!("IO-Link — {} status:{} seq:{} ({})", pdu_type, status, payload[3] & 0x0F, super::bytes(payload.len() as u64))
    } else {
        format!("IO-Link — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IoLink,
        summary,
    }
}
