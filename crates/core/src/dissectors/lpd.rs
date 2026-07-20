// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an LPD message (TCP 515) — the classic Line Printer Daemon protocol
/// still spoken by network printers and print servers. Byte 0 is the command
/// code, followed by the queue name (RFC 1179).
pub fn dissect_lpd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&c @ 1..=5) => {
            let name = match c {
                1 => "print waiting jobs",
                2 => "receive a printer job",
                3 => "send queue state (short)",
                4 => "send queue state (long)",
                _ => "remove jobs",
            };
            let queue = super::first_text_line(&payload[1..]);
            if queue.is_empty() {
                format!("LPD — {name}")
            } else {
                format!("LPD — {name} on {}", super::truncate(&queue, 32))
            }
        }
        _ => format!("LPD data ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lpd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_job() {
        let r = dissect_lpd(None, None, 40000, 515, b"\x02lp\n");
        assert_eq!(r.protocol, Protocol::Lpd);
        assert_eq!(r.summary, "LPD — receive a printer job on lp");
    }
}
