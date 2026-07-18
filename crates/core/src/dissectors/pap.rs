// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PAP packet (PPP protocol 0xC023) — the Password Authentication
/// Protocol, which sends the username **and password in the clear**. Anyone
/// capturing a PAP login has working credentials, which is why CHAP or EAP
/// should be used instead (RFC 1334).
pub fn dissect_pap(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(1) => {
            // Auth-Request: code, id, length(2), peer-id-len, peer-id, …
            let user = body
                .get(4)
                .map(|&n| n as usize)
                .and_then(|n| body.get(5..5 + n))
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            if user.is_empty() {
                "PAP Authenticate-Request (cleartext password)".to_string()
            } else {
                format!(
                    "PAP Authenticate-Request — user {} (cleartext password)",
                    super::truncate(&user, 24)
                )
            }
        }
        Some(2) => "PAP Authenticate-Ack".to_string(),
        Some(3) => "PAP Authenticate-Nak".to_string(),
        _ => "PAP packet".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Pap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_exposes_the_username() {
        // code 1, id, length(2), peer-id len 5, "alice", …
        let mut b = vec![0x01, 0x01, 0x00, 0x10, 0x05];
        b.extend_from_slice(b"alice");
        let r = dissect_pap(&b);
        assert_eq!(r.protocol, Protocol::Pap);
        assert!(r.summary.contains("alice"), "{}", r.summary);
        assert!(r.summary.contains("cleartext"), "{}", r.summary);
    }
}
