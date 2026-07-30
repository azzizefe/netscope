// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OpenFlow message (TCP 6653) — the SDN protocol a controller uses
/// to program switch flow tables. Byte 0 is the version, byte 1 the type
/// (ONF OpenFlow spec).
pub fn dissect_openflow(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                0 => "Hello",
                1 => "Error",
                2 => "Echo Request",
                3 => "Echo Reply",
                5 => "Features Request",
                6 => "Features Reply",
                10 => "Packet-In",
                13 => "Packet-Out",
                14 => "Flow-Mod",
                _ => "message",
            };
            format!("OpenFlow {name}")
        }
        None => "OpenFlow (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenFlow,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_in() {
        // version 0x04 (OF 1.3), type 10 (Packet-In).
        let r = dissect_openflow(None, None, 40000, 6653, &[0x04, 0x0A, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::OpenFlow);
        assert_eq!(r.summary, "OpenFlow Packet-In");
    }
}
