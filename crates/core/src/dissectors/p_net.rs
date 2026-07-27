use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_p_net(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let svc = match payload[0] {
            0x01 => "Read",
            0x02 => "Write",
            0x03 => "Info",
            0x04 => "Status",
            0x05 => "Identify",
            0x06 => "Alarm",
            _ => "Service",
        };
        let node = payload[1];
        format!("P-NET — {} node:{} seg:{} ({} bytes)", svc, node, payload[3], payload.len())
    } else {
        format!("P-NET — {} bytes", payload.len())
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PNet,
        summary,
    }
}
