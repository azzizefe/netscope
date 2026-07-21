// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Modbus/TCP message (TCP 502).
///
/// Modbus is the lingua franca of industrial control (PLCs, SCADA). Over TCP it
/// wraps the classic Modbus PDU in a 7-byte MBAP header: transaction id(2),
/// protocol id(2, always 0), length(2), unit id(1). The PDU that follows is a
/// function code(1) plus data. An exception response ORs 0x80 into the function
/// code and carries a one-byte exception code. We name the function and flag
/// exceptions — the kind of thing an OT security audit wants to see plainly.
pub fn dissect_modbus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Modbus,
        summary,
    };

    if payload.len() < 8 {
        return result("Modbus/TCP (partial)".into());
    }

    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    let unit = payload[6];
    let func = payload[7];

    // Exception response: high bit set, next byte is the exception code.
    if func & 0x80 != 0 {
        let base = func & 0x7f;
        let exc = payload.get(8).copied().unwrap_or(0);
        return result(format!(
            "Modbus Exception — {} ({}), unit {unit}",
            function_name(base),
            exception_name(exc)
        ));
    }

    let _ = protocol_id;
    result(format!(
        "Modbus {} (fn {func}), unit {unit}",
        function_name(func)
    ))
}

/// Whether a TCP payload looks like Modbus/TCP: MBAP protocol-id 0 and a length
/// field that agrees with the bytes present. Used to accept Modbus on ports
/// other than 502 (many gateways relocate it).
pub fn looks_like_modbus(payload: &[u8]) -> bool {
    payload.len() >= 8 && payload[2] == 0 && payload[3] == 0 && {
        let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        // length counts unit id + PDU; sane and roughly matching the frame.
        (1..=253).contains(&len) && payload.len() >= 6 + len.min(payload.len())
    }
}

pub(crate) fn function_name(func: u8) -> &'static str {
    match func {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        7 => "Read Exception Status",
        8 => "Diagnostics",
        11 => "Get Comm Event Counter",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        17 => "Report Server ID",
        22 => "Mask Write Register",
        23 => "Read/Write Multiple Registers",
        43 => "Encapsulated Interface (MEI)",
        _ => "function",
    }
}

pub(crate) fn exception_name(exc: u8) -> &'static str {
    match exc {
        1 => "Illegal Function",
        2 => "Illegal Data Address",
        3 => "Illegal Data Value",
        4 => "Server Device Failure",
        5 => "Acknowledge",
        6 => "Server Device Busy",
        8 => "Memory Parity Error",
        10 => "Gateway Path Unavailable",
        11 => "Gateway Target Failed to Respond",
        _ => "unknown exception",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mbap(func: u8, data: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&1u16.to_be_bytes()); // transaction
        p.extend_from_slice(&0u16.to_be_bytes()); // protocol id
        p.extend_from_slice(&((2 + data.len()) as u16).to_be_bytes()); // length
        p.push(1); // unit
        p.push(func);
        p.extend_from_slice(data);
        p
    }

    #[test]
    fn read_holding_registers() {
        let p = mbap(3, &[0x00, 0x00, 0x00, 0x0a]);
        let r = dissect_modbus(None, None, 50000, 502, &p);
        assert_eq!(r.protocol, Protocol::Modbus);
        assert_eq!(r.summary, "Modbus Read Holding Registers (fn 3), unit 1");
    }

    #[test]
    fn exception_response() {
        let p = mbap(0x83, &[0x02]); // exception on Read Holding Registers
        let r = dissect_modbus(None, None, 502, 50000, &p);
        assert_eq!(
            r.summary,
            "Modbus Exception — Read Holding Registers (Illegal Data Address), unit 1"
        );
    }

    #[test]
    fn detection() {
        let p = mbap(3, &[0x00, 0x00, 0x00, 0x0a]);
        assert!(looks_like_modbus(&p));
        assert!(!looks_like_modbus(b"GET / HTTP/1.1\r\n\r\n"));
    }
}
