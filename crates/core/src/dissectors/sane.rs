// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SANE message (TCP 6566) — the network protocol for sharing
/// scanners on Unix (saned). Each request opens with a 4-byte big-endian RPC
/// opcode.
pub fn dissect_sane(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let op = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let name = match op {
            0 => "INIT",
            1 => "GET_DEVICES",
            2 => "OPEN",
            3 => "CLOSE",
            4 => "GET_OPTION_DESCRIPTORS",
            5 => "CONTROL_OPTION",
            6 => "GET_PARAMETERS",
            7 => "START",
            8 => "CANCEL",
            9 => "AUTHORIZE",
            10 => "EXIT",
            _ => "RPC",
        };
        format!("SANE {name}")
    } else {
        format!("SANE ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sane,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_devices() {
        let r = dissect_sane(None, None, 40000, 6566, &1u32.to_be_bytes());
        assert_eq!(r.protocol, Protocol::Sane);
        assert_eq!(r.summary, "SANE GET_DEVICES");
    }
}
