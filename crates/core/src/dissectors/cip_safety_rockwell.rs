use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cip_safety_rockwell(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let safety_crc = u16::from_be_bytes([payload[0], payload[1]]);
        let signature_lo = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let status = payload.get(6).copied().unwrap_or(0);
        let conn_id = payload.get(7).copied().unwrap_or(0);

        let status_name = match status & 0x0F {
            0x01 => "Safe (no fault)",
            0x02 => "Stop demanded",
            0x03 => "Faulted",
            0x04 => "Config mismatch",
            0x05 => "Discrepancy",
            _ => "Status",
        };

        let guard_logix_ext = if status & 0x80 != 0 {
            " GuardLogix"
        } else {
            ""
        };

        format!("CIP Safety (Rockwell) — {status_name}{guard_logix_ext} sig:0x{signature_lo:08x} CRC:0x{safety_crc:04x} conn:{conn_id} ({len} bytes)", len = payload.len())
    } else {
        format!("CIP Safety (Rockwell) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::CipSafetyRockwell,
        summary,
    }
}
