use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_yaskawa_memobus_tcp_detail(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let trans_id = u16::from_be_bytes([payload[0], payload[1]]);
        let unit_id = payload.get(6).copied().unwrap_or(0);
        let func = payload.get(7).copied().unwrap_or(0);
        let reg_addr = u16::from_be_bytes([payload.get(8).copied().unwrap_or(0), payload.get(9).copied().unwrap_or(0)]);

        let func_name = match func {
            0x03 => "ReadHoldingRegisters",
            0x06 => "WriteSingleRegister",
            0x10 => "WriteMultipleRegisters",
            0x14 => "ReadMultipleRegisters",
            0x17 => "ReadWriteMultipleRegisters",
            0x46 => "YaskawaMemobusSingle",
            0x47 => "YaskawaMemobusBlock",
            0x48 => "Sigma7GatewayRead",
            0x49 => "Sigma7GatewayWrite",
            _ => "MEMOBUS func",
        };

        let sig7 = if func >= 0x48 { " (Sigma-7 GW)" } else { "" };

        format!("Yaskawa MEMOBUS/TCP — {func_name}{sig7} trans:{trans_id} unit:{unit_id} reg:0x{reg_addr:04x} ({len} bytes)", len = payload.len())
    } else {
        format!("Yaskawa MEMOBUS/TCP — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::YaskawaMemobusTcpDetail,
        summary,
    }
}
