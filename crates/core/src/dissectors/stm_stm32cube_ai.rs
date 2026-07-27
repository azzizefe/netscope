use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_stm_stm32cube_ai(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let net = u16::from_le_bytes([payload[0], payload[1]]);
        let state = match payload[2] {
            0x01 => "Initialize",
            0x02 => "Run",
            0x03 => "GetOutput",
            0x04 => "Deinitialize",
            _ => "Unknown",
        };
        let cycles = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        format!("STM32Cube.AI — net:{net} {state} cycles:{cycles} ({})", super::bytes(payload.len() as u64))
    } else {
        format!("STM32Cube.AI — {}", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::StmStm32cubeAi,
        summary,
    }
}
