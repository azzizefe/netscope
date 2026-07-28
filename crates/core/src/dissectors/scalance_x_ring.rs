use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_scalance_x_ring(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let hrp_version = payload[0];
        let ring_state = payload.get(1).copied().unwrap_or(0);
        let port1_state = payload.get(2).copied().unwrap_or(0);
        let port2_state = payload.get(3).copied().unwrap_or(0);
        let ring_id = u32::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
        ]);

        let state_name = match ring_state {
            0x00 => "Open (redundancy)",
            0x01 => "Closed",
            0x02 => "Failure",
            0x03 => "Config changed",
            _ => "Unknown",
        };

        let p1 = match port1_state {
            0x01 => "UP",
            0x02 => "BLOCKED",
            _ => "DOWN",
        };

        let p2 = match port2_state {
            0x01 => "UP",
            0x02 => "BLOCKED",
            _ => "DOWN",
        };

        format!("SCALANCE X Ring — HRP v{hrp_version} ring:0x{ring_id:08x} {state_name} P1:{p1} P2:{p2} ({len} bytes)", len = payload.len())
    } else {
        format!("SCALANCE X Ring — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::ScalanceXRing,
        summary,
    }
}
