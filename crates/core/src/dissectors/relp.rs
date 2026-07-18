// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RELP message (TCP 2514) — Reliable Event Logging Protocol, rsyslog's
/// acknowledged transport that (unlike plain syslog) won't silently drop logs.
/// Each frame is `txnr command datalen [data]`.
pub fn dissect_relp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let mut parts = line.split_whitespace();
    let txnr = parts.next().unwrap_or("");
    let command = parts.next().unwrap_or("");
    let summary = if txnr.chars().all(|c| c.is_ascii_digit()) && !txnr.is_empty() {
        match command {
            "open" => format!("RELP open (txn {txnr})"),
            "close" => format!("RELP close (txn {txnr})"),
            "syslog" => format!("RELP syslog message (txn {txnr})"),
            "rsp" => format!("RELP response (txn {txnr})"),
            "" => format!("RELP frame (txn {txnr})"),
            other => format!("RELP {other} (txn {txnr})"),
        }
    } else {
        format!("RELP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Relp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_frame() {
        let r = dissect_relp(
            None,
            None,
            40000,
            2514,
            b"3 syslog 24 <13>Jan 1 test message\n",
        );
        assert_eq!(r.protocol, Protocol::Relp);
        assert_eq!(r.summary, "RELP syslog message (txn 3)");
    }
}
