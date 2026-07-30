// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check: an RTPS/DDS message begins with the magic "RTPS". DDS
/// uses dynamically assigned ports, so it's recognised by content.
pub fn looks_like_rtps(p: &[u8]) -> bool {
    p.starts_with(b"RTPS")
}

/// Dissect an RTPS message — the wire protocol behind DDS, the pub/sub
/// middleware used in robotics (ROS 2), autonomous vehicles and defence. The
/// first submessage id (at offset 20) names the action.
pub fn dissect_rtps(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let name = match payload.get(20) {
        Some(0x06) => "ACKNACK",
        Some(0x07) => "HEARTBEAT",
        Some(0x09) => "INFO_TS",
        Some(0x0E) => "INFO_DST",
        Some(0x15) => "DATA",
        Some(0x16) => "DATA_FRAG",
        _ => "message",
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rtps,
        summary: format!("RTPS/DDS {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_submessage() {
        let mut p = b"RTPS".to_vec();
        p.extend_from_slice(&[0x02, 0x03]); // version
        p.extend_from_slice(&[0u8; 14]); // vendor + guid prefix
        p.push(0x15); // submessage id: DATA
        assert!(looks_like_rtps(&p));
        let r = dissect_rtps(None, None, 7400, 7401, &p);
        assert_eq!(r.protocol, Protocol::Rtps);
        assert_eq!(r.summary, "RTPS/DDS DATA");
    }
}
