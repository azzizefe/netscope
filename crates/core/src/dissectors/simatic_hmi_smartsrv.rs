use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_simatic_hmi_smartsrv(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let session_id = u16::from_be_bytes([payload[0], payload[1]]);
        let msg_type = payload.get(2).copied().unwrap_or(0);
        let tag_count = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let type_name = match msg_type {
            0x01 => "TagSubscribe",
            0x02 => "TagUpdate",
            0x03 => "TagUnsubscribe",
            0x04 => "AlarmEvent",
            0x05 => "HistoricalRead",
            0x06 => "KeepAlive",
            0x07 => "SessionOpen",
            0x08 => "SessionClose",
            _ => "Msg",
        };

        format!("SIMATIC HMI SmartServer — {type_name} session:{session_id} tags:{tag_count} ({len} bytes)", len = payload.len())
    } else {
        format!("SIMATIC HMI SmartServer — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SimaticHmiSmartsrv,
        summary,
    }
}
