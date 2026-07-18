// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Ident message (TCP 113) — a legacy service that names the user
/// behind a TCP connection. Historically used by IRC servers and mail relays;
/// it leaks local usernames, so it's mostly disabled today (RFC 1413).
pub fn dissect_ident(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.contains("USERID") {
        format!("Ident response — {}", super::truncate(&line, 48))
    } else if line.contains("ERROR") {
        format!("Ident error — {}", super::truncate(&line, 40))
    } else if line.contains(',') {
        format!("Ident query — ports {}", super::truncate(&line, 32))
    } else {
        format!("Ident ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ident,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query() {
        let r = dissect_ident(None, None, 40000, 113, b"6193, 23\r\n");
        assert_eq!(r.protocol, Protocol::Ident);
        assert!(r.summary.starts_with("Ident query"), "{}", r.summary);
    }

    #[test]
    fn response() {
        let r = dissect_ident(
            None,
            None,
            113,
            40000,
            b"6193, 23 : USERID : UNIX : alice\r\n",
        );
        assert!(r.summary.starts_with("Ident response"), "{}", r.summary);
    }
}
