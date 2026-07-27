use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_stratix_switch_telemetry(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let msg_type = payload[0];
        let slot = payload.get(1).copied().unwrap_or(0);
        let port_bits = u32::from_be_bytes([payload.get(2).copied().unwrap_or(0), payload.get(3).copied().unwrap_or(0), payload.get(4).copied().unwrap_or(0), payload.get(5).copied().unwrap_or(0)]);

        let type_name = match msg_type {
            0x01 => "PortMirrorConfig",
            0x02 => "QoSPolicy",
            0x03 => "RingHealth",
            0x04 => "PortStats",
            0x05 => "VLANConfig",
            0x06 => "SNMPBridge",
            _ => "Stratix msg",
        };

        let port_count = port_bits.count_ones();

        format!("Stratix Switch Telemetry — {type_name} slot:{slot} ports:{port_count} ({len} bytes)", len = payload.len())
    } else {
        format!("Stratix Switch Telemetry — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::StratixSwitchTelemetry,
        summary,
    }
}
