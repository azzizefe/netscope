// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a CHAP packet (PPP protocol 0xC223) — Challenge-Handshake
/// Authentication, which proves knowledge of a shared secret with a hash
/// instead of sending it, unlike PAP (RFC 1994).
pub fn dissect_chap(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(1) => {
            // Challenge: code, id, length(2), value-size, value, name…
            let name_start = body.get(4).map(|&n| 5 + n as usize).unwrap_or(usize::MAX);
            let name = body
                .get(name_start..)
                .map(|b| String::from_utf8_lossy(b).trim().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                "CHAP Challenge".to_string()
            } else {
                format!("CHAP Challenge from {}", super::truncate(&name, 24))
            }
        }
        Some(2) => "CHAP Response".to_string(),
        Some(3) => "CHAP Success".to_string(),
        Some(4) => "CHAP Failure".to_string(),
        _ => "CHAP packet".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Chap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_names_the_authenticator() {
        let mut b = vec![0x01, 0x01, 0x00, 0x17, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        b.extend_from_slice(b"gateway");
        let r = dissect_chap(&b);
        assert_eq!(r.protocol, Protocol::Chap);
        assert!(r.summary.contains("gateway"), "{}", r.summary);
    }

    #[test]
    fn success() {
        let r = dissect_chap(&[0x03, 0x01, 0x00, 0x04]);
        assert_eq!(r.summary, "CHAP Success");
    }
}
