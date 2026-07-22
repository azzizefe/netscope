// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Fanuc FOCAS command function descriptions.
fn command_name(cmd: u16) -> &'static str {
    match cmd {
        0x0001 => "cnc_allclldata (Sys Info)",
        0x0002 => "cnc_statinfo (Status Info)",
        0x000A => "cnc_rdaxis (Read Axis Data)",
        0x0014 => "cnc_rdgcode (Read G-Code)",
        0x001E => "cnc_wrgcode (Write G-Code)",
        0x0028 => "cnc_rdparam (Read Parameter)",
        0x0029 => "cnc_wrparam (Write Parameter)",
        0x0032 => "cnc_rdmacro (Read Macro)",
        0x0033 => "cnc_wrmacro (Write Macro)",
        0x0040 => "cnc_rdpmc (Read PMC)",
        0x0041 => "cnc_wrpmc (Write PMC)",
        0x0050 => "cnc_alarm (Read Alarms)",
        0x0060 => "cnc_modal (Read Modal)",
        _ => "Command",
    }
}

/// Dissect a Fanuc FOCAS / FOCAS2 CNC Ethernet communication frame on TCP port 8193.
pub fn dissect_focas(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        format!("FOCAS ({})", super::bytes(payload.len() as u64))
    } else {
        let cmd = u16::from_be_bytes([payload[0], payload[1]]);
        let cname = command_name(cmd);
        if cname == "Command" {
            format!("FOCAS command {cmd:#06x}")
        } else {
            format!("FOCAS {cname}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Focas,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_focas_statinfo() {
        let payload = vec![0x00, 0x02, 0x00, 0x00];
        let res = dissect_focas(None, None, 40000, 8193, &payload);
        assert_eq!(res.protocol, Protocol::Focas);
        assert!(res.summary.contains("cnc_statinfo"));
    }

    #[test]
    fn test_focas_short_payload() {
        let payload = vec![0x01];
        let res = dissect_focas(None, None, 40000, 8193, &payload);
        assert_eq!(res.protocol, Protocol::Focas);
        assert!(res.summary.contains("FOCAS (1 byte)"));
    }
}
