use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_twincat_scope_view(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let session = u16::from_be_bytes([payload[0], payload[1]]);
        let channel_count = payload.get(2).copied().unwrap_or(0);
        let acquisition_mode = payload.get(3).copied().unwrap_or(0);
        let sample_rate = u32::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
        ]);

        let mode_name = match acquisition_mode {
            0x01 => "Continuous",
            0x02 => "Triggered",
            0x03 => "SingleShot",
            0x04 => "YXScatter",
            _ => "Scope mode",
        };

        format!("TwinCAT Scope View — {mode_name} session:{session} channels:{channel_count} rate:{sample_rate}Hz ({len} bytes)", len = payload.len())
    } else {
        format!("TwinCAT Scope View — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::TwincatScopeView,
        summary,
    }
}
