// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Protocol Heuristics & Signature Validation Engine.
//!
//! Provides structural heuristics and magic-signature matching to safely validate
//! un-bound or runtime-negotiated protocols without false-positive port collisions.

use crate::models::Protocol;

/// Result of a heuristic inspection on a raw payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeuristicMatch {
    pub protocol: Protocol,
    pub confidence: u8, // 0..100
    pub label: String,
}

/// Validates whether a raw byte slice begins with a known binary magic signature.
#[inline]
pub fn matches_magic(payload: &[u8], magic: &[u8]) -> bool {
    payload.len() >= magic.len() && &payload[..magic.len()] == magic
}

/// Checks if a payload satisfies minimum length and structural checksum/header constraints.
pub fn validate_bounded_frame(payload: &[u8], min_len: usize, magic: Option<&[u8]>) -> bool {
    if payload.len() < min_len {
        return false;
    }
    if let Some(m) = magic {
        if !matches_magic(payload, m) {
            return false;
        }
    }
    true
}

/// Heuristic inspector for PQC monitoring frames.
pub fn inspect_pqc_frame(payload: &[u8]) -> Option<HeuristicMatch> {
    if validate_bounded_frame(payload, 4, Some(b"PQC\x01")) {
        Some(HeuristicMatch {
            protocol: Protocol::Tls,
            confidence: 95,
            label: "PQC Compliance Frame".to_string(),
        })
    } else {
        None
    }
}

/// Heuristic inspector for CANopen frames.
pub fn inspect_canopen_frame(payload: &[u8]) -> Option<HeuristicMatch> {
    if validate_bounded_frame(payload, 8, Some(b"CANO")) {
        Some(HeuristicMatch {
            protocol: Protocol::Can,
            confidence: 90,
            label: "CANopen Frame".to_string(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_magic() {
        assert!(matches_magic(b"PQC\x01payload", b"PQC\x01"));
        assert!(!matches_magic(b"HTTP/1.1", b"PQC\x01"));
        assert!(!matches_magic(b"PQC", b"PQC\x01"));
    }

    #[test]
    fn test_validate_bounded_frame() {
        assert!(validate_bounded_frame(b"PQC\x01data", 4, Some(b"PQC\x01")));
        assert!(!validate_bounded_frame(b"PQC\x01", 10, Some(b"PQC\x01")));
        assert!(!validate_bounded_frame(b"FAILdata", 4, Some(b"PQC\x01")));
    }

    #[test]
    fn test_inspect_pqc_frame() {
        let match_res = inspect_pqc_frame(b"PQC\x01test_bytes");
        assert!(match_res.is_some());
        let m = match_res.unwrap();
        assert_eq!(m.confidence, 95);
        assert_eq!(m.label, "PQC Compliance Frame");
    }
}
