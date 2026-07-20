// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an rsync message (TCP 873) — the file-sync protocol's native daemon
/// transport. A session opens with the greeting `@RSYNCD: <version>`.
pub fn dissect_rsync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"@RSYNCD:") {
        let line = super::first_text_line(payload);
        format!("rsync daemon — {}", super::truncate(&line, 40))
    } else {
        format!("rsync data ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rsync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting() {
        let r = dissect_rsync(None, None, 40000, 873, b"@RSYNCD: 31.0\n");
        assert_eq!(r.protocol, Protocol::Rsync);
        assert!(r.summary.contains("@RSYNCD: 31.0"), "{}", r.summary);
    }
}
