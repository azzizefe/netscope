use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_siemens_industrial_5g(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let msg_type = payload[0];
        let nf_type = payload.get(1).copied().unwrap_or(0);
        let session = u32::from_be_bytes([payload.get(2).copied().unwrap_or(0), payload.get(3).copied().unwrap_or(0), payload.get(4).copied().unwrap_or(0), payload.get(5).copied().unwrap_or(0)]);

        let type_name = match msg_type {
            0x01 => "UPF config",
            0x02 => "NEF expose",
            0x03 => "TSN bridge",
            0x04 => "QoS flow",
            0x05 => "Slice mgmt",
            0x06 => "UE registration",
            _ => "5G msg",
        };

        let nf_name = match nf_type {
            0x01 => "UPF",
            0x02 => "NEF",
            0x03 => "SMF",
            0x04 => "AMF",
            _ => "NF",
        };

        format!("Siemens Industrial 5G — {type_name} ({nf_name}) session:0x{session:08x} ({len} bytes)", len = payload.len())
    } else {
        format!("Siemens Industrial 5G — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SiemensIndustrial5g,
        summary,
    }
}
