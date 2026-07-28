use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_ether_net_ip_rockwell(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let cmd = u16::from_be_bytes([payload[0], payload[1]]);
        let service = payload.get(2).copied().unwrap_or(0);
        let path_len = payload.get(3).copied().unwrap_or(0);

        let service_name = match service {
            0x4B => "ForwardOpenExt",
            0x54 => "ForwardCloseExt",
            0x52 => "LargeForwardOpen",
            0x01 => "GetAttrAll",
            0x0E => "GetAttrSingle",
            0x10 => "SetAttrSingle",
            0x4C => "MultipleService",
            0x4E => "ConnectedDataExt",
            _ => "CIP service",
        };

        let cmd_name = match cmd {
            0x0063 => "RegisterSession",
            0x0064 => "UnregisterSession",
            0x0065 => "ListIdentity",
            0x006F => "SendRRData",
            0x0070 => "SendUnitData",
            _ => "ENIP cmd",
        };

        format!(
            "EtherNet/IP (Rockwell) — {cmd_name} {service_name} path:{path_len} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("EtherNet/IP (Rockwell) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::EtherNetIpRockwell,
        summary,
    }
}
