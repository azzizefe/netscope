// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Syncthing Block Exchange Protocol (BEP v1, TCP 22000).
pub fn dissect_syncthing(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 && payload[0..4] == [0x2E, 0xA7, 0xD9, 0x0B] {
        if payload.len() >= 8 {
            let msg_type = payload[5];
            let name = match msg_type {
                0 => "ClusterConfig",
                1 => "Index",
                2 => "IndexUpdate",
                3 => "Request",
                4 => "Response",
                5 => "Ping",
                6 => "Close",
                _ => "BEP Message",
            };
            format!("Syncthing BEP {name}")
        } else {
            "Syncthing BEP Magic Header".to_string()
        }
    } else {
        format!("Syncthing BEP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Syncthing,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syncthing_bep() {
        let payload = vec![0x2E, 0xA7, 0xD9, 0x0B, 0x00, 0x01, 0x00, 0x00]; // Index
        let r = dissect_syncthing(None, None, 40000, 22000, &payload);
        assert_eq!(r.protocol, Protocol::Syncthing);
        assert_eq!(r.summary, "Syncthing BEP Index");
    }
}
