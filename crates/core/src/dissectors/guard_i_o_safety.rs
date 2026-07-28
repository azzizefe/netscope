use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_guard_i_o_safety(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let module_status = payload[0];
        let channel_bits = u16::from_be_bytes([
            payload.get(1).copied().unwrap_or(0),
            payload.get(2).copied().unwrap_or(0),
        ]);
        let discrepancy = u16::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);

        let status_name = match module_status & 0x0F {
            0x00 => "Safe state",
            0x01 => "Run (no fault)",
            0x02 => "Stop demanded",
            0x03 => "Faulted (individual)",
            0x04 => "Discrepancy",
            _ => "Status",
        };

        let ch_count = channel_bits.count_ones() as u8;
        let fault_channels = if module_status & 0x03 == 0x03 && channel_bits > 0 {
            format!(" faultCh:0x{channel_bits:04x}")
        } else {
            String::new()
        };

        let disc_info = if discrepancy > 0 {
            format!(" disc:{discrepancy}ms")
        } else {
            String::new()
        };

        format!("Guard I/O Safety — {status_name}{fault_channels}{disc_info} activeCh:{ch_count} ({len} bytes)", len = payload.len())
    } else {
        format!("Guard I/O Safety — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::GuardIOSafety,
        summary,
    }
}
