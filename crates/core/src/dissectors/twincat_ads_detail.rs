use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_twincat_ads_detail(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let ams_netid_src = &payload[..6];
        let ams_netid_dst = &payload[6..12];
        let cmd_id = u16::from_be_bytes([
            payload.get(12).copied().unwrap_or(0),
            payload.get(13).copied().unwrap_or(0),
        ]);
        let invoke_id = u32::from_be_bytes([
            payload.get(14).copied().unwrap_or(0),
            payload.get(15).copied().unwrap_or(0),
            payload.get(16).copied().unwrap_or(0),
            payload.get(17).copied().unwrap_or(0),
        ]);

        let cmd_name = match cmd_id {
            0x0001 => "Read",
            0x0002 => "Write",
            0x0003 => "ReadState",
            0x0004 => "WriteControl",
            0x0005 => "AddNotification",
            0x0006 => "DeleteNotification",
            0x0007 => "NotifyData",
            0x0008 => "ReadWrite",
            0x8001 => "SumRead",
            0x8002 => "SumWrite",
            _ => "ADS cmd",
        };

        let src_str = format!(
            "{}.{}.{}.{}.{}.{}",
            ams_netid_src[0],
            ams_netid_src[1],
            ams_netid_src[2],
            ams_netid_src[3],
            ams_netid_src[4],
            ams_netid_src[5]
        );
        let dst_str = format!(
            "{}.{}.{}.{}.{}.{}",
            ams_netid_dst[0],
            ams_netid_dst[1],
            ams_netid_dst[2],
            ams_netid_dst[3],
            ams_netid_dst[4],
            ams_netid_dst[5]
        );

        format!("TwinCAT ADS (Detail) — {cmd_name} {src_str} → {dst_str} invoke:{invoke_id} ({len} bytes)", len = payload.len())
    } else {
        format!("TwinCAT ADS (Detail) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::TwincatAdsDetail,
        summary,
    }
}
