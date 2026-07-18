// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a collectd message (UDP 25826) — the binary metric protocol the
/// collectd daemon uses to ship system statistics. The payload is a series of
/// type/length parts; the first part's type names what the packet opens with.
pub fn dissect_collectd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let part = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match part {
            0x0000 => "host",
            0x0001 => "time",
            0x0002 => "plugin",
            0x0003 => "plugin instance",
            0x0004 => "type",
            0x0005 => "type instance",
            0x0006 => "values",
            0x0008 => "time (high-res)",
            0x0100 => "message",
            0x0101 => "severity",
            _ => "part",
        };
        format!("collectd — {name} part")
    } else {
        format!("collectd ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Collectd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_part() {
        let r = dissect_collectd(None, None, 40000, 25826, &[0x00, 0x00, 0x00, 0x0c]);
        assert_eq!(r.protocol, Protocol::Collectd);
        assert_eq!(r.summary, "collectd — host part");
    }
}
