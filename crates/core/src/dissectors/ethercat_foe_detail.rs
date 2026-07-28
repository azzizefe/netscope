use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_ethercat_foe_detail(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let opcode = payload[0];
        let packet_no = u16::from_be_bytes([
            payload.get(1).copied().unwrap_or(0),
            payload.get(2).copied().unwrap_or(0),
        ]);
        let password = u32::from_be_bytes([
            payload.get(3).copied().unwrap_or(0),
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
            payload.get(6).copied().unwrap_or(0),
        ]);

        let op_name = match opcode {
            0x01 => "Read (request)",
            0x02 => "Read (response)",
            0x03 => "Write (request)",
            0x04 => "Write (response)",
            0x05 => "Data",
            0x06 => "Ack",
            0x07 => "Error",
            0x08 => "Busy",
            _ => "FoE op",
        };

        let pw = if password > 0 {
            format!(" pw:0x{password:08x}")
        } else {
            String::new()
        };

        format!(
            "EtherCAT FoE (Detail) — {op_name} packet:{packet_no}{pw} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("EtherCAT FoE (Detail) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::EthercatFoeDetail,
        summary,
    }
}
