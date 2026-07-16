// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SSDP message (UDP 1900). SSDP is UPnP discovery in an
/// HTTP-like text form: `M-SEARCH` (search), `NOTIFY` (announce), or an
/// `HTTP/1.1 200 OK` search response.
pub fn dissect_ssdp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("M-SEARCH") {
        "SSDP M-SEARCH — device discovery".to_string()
    } else if line.starts_with("NOTIFY") {
        "SSDP NOTIFY — device announcement".to_string()
    } else if line.starts_with("HTTP/") {
        format!("SSDP Response — {}", super::truncate(&line, 50))
    } else if line.is_empty() {
        format!("SSDP ({} bytes)", payload.len())
    } else {
        format!("SSDP — {}", super::truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ssdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msearch() {
        let r = dissect_ssdp(None, None, 40000, 1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n");
        assert_eq!(r.protocol, Protocol::Ssdp);
        assert_eq!(r.summary, "SSDP M-SEARCH — device discovery");
    }

    #[test]
    fn notify() {
        let r = dissect_ssdp(None, None, 1900, 1900, b"NOTIFY * HTTP/1.1\r\n");
        assert_eq!(r.summary, "SSDP NOTIFY — device announcement");
    }
}
