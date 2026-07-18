// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name an IPP operation id (RFC 8011).
fn operation_name(op: u16) -> &'static str {
    match op {
        0x0002 => "Print-Job",
        0x0004 => "Validate-Job",
        0x0005 => "Create-Job",
        0x0006 => "Send-Document",
        0x0008 => "Cancel-Job",
        0x0009 => "Get-Job-Attributes",
        0x000A => "Get-Jobs",
        0x000B => "Get-Printer-Attributes",
        0x4001 => "CUPS-Get-Default",
        0x4002 => "CUPS-Get-Printers",
        _ => "operation",
    }
}

/// Dissect an IPP message (TCP 631) — the Internet Printing Protocol behind
/// CUPS and modern network printers. IPP rides on HTTP, so a request begins
/// with HTTP headers and the IPP body follows the blank line: version(2),
/// operation-id(2), request-id(4).
pub fn dissect_ipp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Find the IPP body after the HTTP headers, if headers are present.
    let body = match memchr::memmem::find(payload, b"\r\n\r\n") {
        Some(i) => &payload[i + 4..],
        None => payload,
    };
    let summary = if body.len() >= 8 && (body[0] == 1 || body[0] == 2) {
        let op = u16::from_be_bytes([body[2], body[3]]);
        format!("IPP {}.{} {}", body[0], body[1], operation_name(op))
    } else if payload.starts_with(b"HTTP/") {
        format!("IPP response ({} bytes)", payload.len())
    } else {
        format!("IPP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ipp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_job_after_http_headers() {
        let mut p = b"POST /printers/hp HTTP/1.1\r\nContent-Type: application/ipp\r\n\r\n".to_vec();
        p.extend_from_slice(&[0x02, 0x00]); // version 2.0
        p.extend_from_slice(&0x0002u16.to_be_bytes()); // Print-Job
        p.extend_from_slice(&1u32.to_be_bytes()); // request id
        let r = dissect_ipp(None, None, 40000, 631, &p);
        assert_eq!(r.protocol, Protocol::Ipp);
        assert_eq!(r.summary, "IPP 2.0 Print-Job");
    }
}
