// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for MMS: TPKT on port 102 carrying an ISO 8327 session
/// SPDU rather than the S7 protocol id. Both share port 102, so the byte at
/// offset 7 is what tells them apart.
pub fn looks_like_mms(p: &[u8]) -> bool {
    matches!(p.first(), Some(0x03))
        && matches!(p.get(7), Some(0x0d) | Some(0x01) | Some(0x0e) | Some(0x08))
}

/// Dissect an MMS message (TCP 102) — Manufacturing Message Specification, the
/// client/server half of IEC 61850 substation communication (reading data
/// models, reports, control). Rides TPKT + ISO COTP + ISO session.
pub fn dissect_mms(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(7) {
        Some(0x0d) => "MMS — session CONNECT (association request)".to_string(),
        Some(0x0e) => "MMS — session ACCEPT (association response)".to_string(),
        Some(0x08) => "MMS — session REFUSE".to_string(),
        Some(0x01) => "MMS — data transfer".to_string(),
        _ => format!("MMS ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mms,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_connect() {
        // TPKT(4) + COTP(3) then session SPDU 0x0d (CONNECT).
        let p = [0x03, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80, 0x0d];
        assert!(looks_like_mms(&p));
        let r = dissect_mms(None, None, 40000, 102, &p);
        assert_eq!(r.protocol, Protocol::Mms);
        assert!(r.summary.contains("CONNECT"), "{}", r.summary);
    }

    #[test]
    fn s7_is_not_mistaken_for_mms() {
        // The same framing but with the S7 protocol id 0x32 at offset 7.
        let p = [0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 0x32];
        assert!(!looks_like_mms(&p));
    }
}
