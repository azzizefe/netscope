// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect WebDAV HTTP Extensions (TCP 80 / 443).
pub fn dissect_webdav(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"PROPFIND ") || payload.starts_with(b"PROPPATCH ") || payload.starts_with(b"MKCOL ") || payload.starts_with(b"COPY ") || payload.starts_with(b"MOVE ") || payload.starts_with(b"LOCK ") || payload.starts_with(b"UNLOCK ") {
        "WebDAV HTTP request".to_string()
    } else {
        format!("WebDAV ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Webdav,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webdav_test() {
        let r = dissect_webdav(None, None, 40000, 80, b"PROPFIND /files HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Webdav);
        assert_eq!(r.summary, "WebDAV HTTP request");
    }
}
