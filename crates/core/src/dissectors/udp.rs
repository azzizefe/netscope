use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_udp(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, payload: &[u8]) -> DissectedResult {
    if payload.len() < 8 {
        return DissectedResult {
            src_addr: src_ip, dst_addr: dst_ip,
            src_port: None, dst_port: None,
            protocol: Protocol::Udp,
            summary: "Malformed UDP header".into(),
        };
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::Udp,
        summary: format!("UDP {} → {} ({} bytes)", src_port, dst_port, len),
    }
}
