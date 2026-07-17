// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Subversion `svn://` message (TCP 3690) — the svnserve protocol.
/// It uses a Lisp-like tuple syntax; a server greeting starts `( success (`.
pub fn dissect_svn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(64)]);
    let t = text.trim_start();
    let summary = if t.starts_with("( success") {
        "SVN — server greeting".to_string()
    } else if t.starts_with("( failure") {
        "SVN — error response".to_string()
    } else if t.starts_with('(') {
        "SVN command".to_string()
    } else {
        format!("SVN data ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Svn,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting() {
        let r = dissect_svn(None, None, 40000, 3690, b"( success ( 2 2 ( ) ( edit-pipeline ) ) ) ");
        assert_eq!(r.protocol, Protocol::Svn);
        assert_eq!(r.summary, "SVN — server greeting");
    }
}
