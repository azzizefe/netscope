use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_profinet_irt_siemens(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        let sync_domain = payload[2];
        let sub_frame_count = payload[4];

        let irt_type = match frame_id {
            f if (0x0000..=0x007F).contains(&f) => "Isochronous (IRT)",
            f if (0x0080..=0x00FF).contains(&f) => "Isoch. with jitter (IRT-2)",
            f if (0x0100..=0x01FF).contains(&f) => "High performance (IRT-3)",
            _ => "IRT frame",
        };

        let sync_ext = if sync_domain > 0 {
            format!(" syncDomain:{sync_domain}")
        } else {
            String::new()
        };

        format!("PROFINET IRT (Siemens) — {irt_type}{sync_ext} subFrames:{sub_frame_count} ({len} bytes)", len = payload.len())
    } else {
        format!("PROFINET IRT (Siemens) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::ProfinetIrtSiemens,
        summary,
    }
}
