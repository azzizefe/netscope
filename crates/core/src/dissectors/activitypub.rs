// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect ActivityPub Protocol (TCP 443).
pub fn dissect_activitypub(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.contains(&b"application/activity+json") || payload.contains(&b"application/ld+json") {
        "ActivityPub payload".to_string()
    } else {
        format!("ActivityPub ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Activitypub,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activitypub_test() {
        let r = dissect_activitypub(None, None, 40000, 443, b"POST /inbox HTTP/1.1\r\nContent-Type: application/activity+json\r\n");
        assert_eq!(r.protocol, Protocol::Activitypub);
        assert_eq!(r.summary, "ActivityPub payload");
    }
}
