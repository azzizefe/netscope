use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_omron_fins_udp_detail(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let icf = payload[0];
        let gct = payload[2];
        let dna = payload[3];
        let da1 = payload[4];
        let da2 = payload[5];
        let sna = payload[6];
        let sa1 = payload[7];
        let mrc = payload.get(8).copied().unwrap_or(0);
        let src = payload.get(9).copied().unwrap_or(0);

        let cmd_name = match (mrc, src) {
            (0x01, 0x01) => "MemoryRead",
            (0x01, 0x02) => "MemoryWrite",
            (0x01, 0x03) => "MemoryFill",
            (0x01, 0x04) => "MultipleMemRead",
            (0x02, 0x01) => "ClockRead",
            (0x02, 0x02) => "ClockWrite",
            (0x03, 0x01) => "NetConfigRead",
            (0x03, 0x02) => "NetConfigWrite",
            (0x04, 0x01) => "ControllerStatus",
            (0x05, 0x01) => "ProgramRead",
            (0x05, 0x02) => "ProgramWrite",
            (0x06, 0x01) => "Run",
            (0x06, 0x02) => "Stop",
            _ => "FINS cmd",
        };

        let is_response = icf & 0x80 != 0;
        let frame = if is_response { "Response" } else { "Request" };

        format!("OMRON FINS/UDP (Detail) — {cmd_name} {frame} dst:{dna}.{da1}.{da2} src:{sna}.{sa1} gct:{gct} ({len} bytes)", len = payload.len())
    } else {
        format!("OMRON FINS/UDP (Detail) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::OmronFinsUdpDetail,
        summary,
    }
}
