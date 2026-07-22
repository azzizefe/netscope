// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Toyopuc Computer Link command descriptions.
fn command_type(cmd: u8) -> &'static str {
    match cmd {
        b'R' | b'r' => "Read Data",
        b'W' | b'w' => "Write Data",
        b'E' | b'e' => "Echo Test",
        b'C' | b'c' => "Control / Status",
        b'M' | b'm' => "Multi-Read",
        _ => "Command",
    }
}

/// Device/Register type descriptions.
fn device_name(dev: u8) -> Option<&'static str> {
    Some(match dev {
        b'M' => "Internal Relay (M)",
        b'P' => "Programmable Flag (P)",
        b'K' => "Keep Relay (K)",
        b'V' => "Edge Relay (V)",
        b'T' => "Timer (T)",
        b'C' => "Counter (C)",
        b'D' => "Data Register (D)",
        b'B' => "File Register (B)",
        b'S' => "Special Register (S)",
        _ => return None,
    })
}

/// Dissect a JTEKT Toyopuc PLC Computer Link frame on TCP/UDP port 4096.
pub fn dissect_toyopuc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        format!("Toyopuc ({})", super::bytes(payload.len() as u64))
    } else {
        let cmd = payload[0];
        let ctype = command_type(cmd);
        let cpu_no = payload[1];
        let target_cpu = if (1..=4).contains(&cpu_no) {
            format!("CPU{cpu_no}")
        } else {
            format!("CPU (0x{cpu_no:02x})")
        };

        if payload.len() >= 3 {
            if let Some(dev) = device_name(payload[2]) {
                format!("Toyopuc {ctype} — {target_cpu} {dev}")
            } else {
                format!("Toyopuc {ctype} — {target_cpu}")
            }
        } else {
            format!("Toyopuc {ctype} — {target_cpu}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Toyopuc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toyopuc_read_register() {
        // Command 'R', CPU 1, Register 'D' (Data Register)
        let payload = vec![b'R', 0x01, b'D', 0x00, 0x00];
        let res = dissect_toyopuc(None, None, 40000, 4096, &payload);
        assert_eq!(res.protocol, Protocol::Toyopuc);
        assert!(res.summary.contains("Read Data"));
        assert!(res.summary.contains("CPU1 Data Register (D)"));
    }

    #[test]
    fn test_toyopuc_short_payload() {
        let payload = vec![b'R'];
        let res = dissect_toyopuc(None, None, 40000, 4096, &payload);
        assert_eq!(res.protocol, Protocol::Toyopuc);
        assert!(res.summary.contains("Toyopuc (1 byte)"));
    }
}
