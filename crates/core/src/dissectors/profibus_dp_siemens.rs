use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

const SD1_FIXED_WITHOUT_FC: u8 = 0x05;
const SD2_VARIABLE_LENGTH: u8 = 0x68;
const SD3_FIXED_WITH_FC: u8 = 0x07;
const SD4_FIXED_TOKEN: u8 = 0x0C;
pub fn dissect_profibus_dp_siemens(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 {
        let sd = payload[0];
        let fc = payload.get(1).copied().unwrap_or(0);
        let dp_version = payload.get(2).copied().unwrap_or(0);

        let sd_name = match sd {
            SD1_FIXED_WITHOUT_FC => "SD1 (short ack)",
            SD2_VARIABLE_LENGTH => "SD2 (variable telegram)",
            SD3_FIXED_WITH_FC => "SD3 (fixed telegram)",
            SD4_FIXED_TOKEN => "SD4 (token)",
            _ => "unknown SD",
        };

        let version_info = match dp_version {
            0x20 => "DP-V0",
            0x21 => "DP-V1",
            0x22 => "DP-V2",
            0x23 => "DP-V3 (Siemens ext)",
            _ => "",
        };

        format!("PROFIBUS DP (Siemens) — {sd_name} fc:0x{fc:02x} {version_info} ({len} bytes)", len = payload.len())
    } else {
        format!("PROFIBUS DP (Siemens) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::ProfibusDpSiemens,
        summary,
    }
}
