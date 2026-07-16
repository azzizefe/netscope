// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Git protocol message (TCP 9418) — the native `git://` transport.
/// A session opens with a pkt-line naming the service (`git-upload-pack` for
/// clone/fetch, `git-receive-pack` for push).
pub fn dissect_git(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(256)]);
    let summary = if text.contains("git-upload-pack") {
        "Git — upload-pack (clone/fetch)".to_string()
    } else if text.contains("git-receive-pack") {
        "Git — receive-pack (push)".to_string()
    } else {
        format!("Git peer message ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Git,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_pack() {
        let r = dissect_git(
            None,
            None,
            40000,
            9418,
            b"0032git-upload-pack /repo.git\0host=example.com\0",
        );
        assert_eq!(r.protocol, Protocol::Git);
        assert_eq!(r.summary, "Git — upload-pack (clone/fetch)");
    }
}
