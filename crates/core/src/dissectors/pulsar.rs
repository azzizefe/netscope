// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Apache Pulsar message (TCP 6650) — the broker protocol for the
/// distributed messaging system. Each frame is a 4-byte total size followed by
/// a 4-byte command size and a protobuf BaseCommand.
pub fn dissect_pulsar(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let total = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let cmd = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        // A sane frame has a command that fits inside the declared total.
        if cmd as usize + 4 <= total as usize {
            format!("Pulsar command ({cmd} byte command, {total} byte frame)")
        } else {
            format!("Pulsar payload ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("Pulsar ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pulsar,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frame() {
        let mut p = 20u32.to_be_bytes().to_vec(); // total size
        p.extend_from_slice(&10u32.to_be_bytes()); // command size
        p.extend_from_slice(&[0u8; 10]);
        let r = dissect_pulsar(None, None, 40000, 6650, &p);
        assert_eq!(r.protocol, Protocol::Pulsar);
        assert!(r.summary.contains("10 byte command"), "{}", r.summary);
    }
}
