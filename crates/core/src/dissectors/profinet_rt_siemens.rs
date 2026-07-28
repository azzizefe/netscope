use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

const FRAME_ID_ALARM_HIGH: u16 = 0xFC01;
const FRAME_ID_ALARM_LOW: u16 = 0xFE01;

const SIEMENS_ALARM_CHANNEL_NUMBER: u8 = 0xA0;
const SIEMENS_DIAG_CHANNEL_NUMBER: u8 = 0xA1;

pub fn dissect_profinet_rt_siemens(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        let channel = payload.get(2).copied().unwrap_or(0);
        let io_data_obj = payload.get(3).copied().unwrap_or(0);
        let frame_type = match frame_id {
            FRAME_ID_ALARM_HIGH => "Alarm (Siemens high)",
            FRAME_ID_ALARM_LOW => "Alarm (Siemens low)",
            f if (0x8000..=0xBBFF).contains(&f) => "RT Class 1 (cyclic)",
            f if (0xC000..=0xFBFF).contains(&f) => "RT Class 2 (acyclic)",
            _ => "RT frame",
        };
        let channel_name = match channel {
            SIEMENS_ALARM_CHANNEL_NUMBER => " Siemens alarm channel",
            SIEMENS_DIAG_CHANNEL_NUMBER => " Siemens diagnosis channel",
            _ => "",
        };
        format!("PROFINET RT (Siemens) — {frame_type}{channel_name} ioDataObj:{io_data_obj} ({len} bytes)", len = payload.len())
    } else {
        format!("PROFINET RT (Siemens) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::ProfinetRtSiemens,
        summary,
    }
}
