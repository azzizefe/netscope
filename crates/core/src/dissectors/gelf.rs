// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GELF message (UDP 12201) — the Graylog Extended Log Format for
/// shipping structured logs. The leading bytes reveal the framing: a chunked
/// magic, gzip/zlib compression, or raw JSON.
pub fn dissect_gelf(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let encoding = match (payload.first(), payload.get(1)) {
        (Some(0x1e), Some(0x0f)) => "chunked",
        (Some(0x1f), Some(0x8b)) => "gzip",
        (Some(0x78), _) => "zlib",
        (Some(b'{'), _) => "uncompressed JSON",
        _ => "message",
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gelf,
        summary: format!("GELF (Graylog) — {encoding}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked() {
        let r = dissect_gelf(None, None, 40000, 12201, &[0x1e, 0x0f, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Gelf);
        assert_eq!(r.summary, "GELF (Graylog) — chunked");
    }
}
