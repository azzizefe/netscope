// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Mercurial wire protocol messages (TCP 2000 hg serve).
pub fn dissect_mercurial(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        let first_line = s.lines().next().unwrap_or("").trim();
        if !first_line.is_empty() {
            let cmd = first_line.split_whitespace().next().unwrap_or(first_line);
            match cmd {
                "capabilities" | "batch" | "between" | "branches" | "changegroup" | "heads"
                | "lookup" | "unbundle" | "pushkey" | "listkeys" => {
                    format!("Mercurial Command · {cmd}")
                }
                _ => format!("Mercurial wire protocol ({})", super::bytes(payload.len() as u64)),
            }
        } else {
            format!("Mercurial wire protocol ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("Mercurial wire protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mercurial,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mercurial_heads() {
        let payload = b"heads\n";
        let r = dissect_mercurial(None, None, 40000, 2000, payload);
        assert_eq!(r.protocol, Protocol::Mercurial);
        assert_eq!(r.summary, "Mercurial Command · heads");
    }
}
