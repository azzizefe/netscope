// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every Ceph messenger v1 connection opens with this banner, which is what
/// makes the protocol recognisable regardless of which port a daemon landed on.
const BANNER: &[u8] = b"ceph v027";

/// Messenger v1 tags (Ceph `msgr` protocol). The tag is the first byte of every
/// frame once the connection is established.
fn tag_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        1 => "READY",
        2 => "RESETSESSION",
        3 => "WAIT",
        4 => "RETRY_SESSION",
        5 => "RETRY_GLOBAL",
        6 => "CLOSE",
        7 => "MSG",
        8 => "ACK",
        9 => "KEEPALIVE",
        10 => "BADPROTOVER",
        11 => "BADAUTHORIZER",
        12 => "FEATURES",
        13 => "SEQ",
        14 => "KEEPALIVE2",
        15 => "KEEPALIVE2_ACK",
        _ => return None,
    })
}

/// Whether a payload is Ceph traffic. Only the banner is distinctive enough to
/// claim a connection; the tag bytes on their own are far too weak.
pub(crate) fn looks_like_ceph(payload: &[u8]) -> bool {
    payload.starts_with(BANNER)
}

/// Dissect a Ceph messenger message — the protocol Ceph's monitors, metadata
/// servers and object storage daemons use to talk to each other and to clients,
/// on TCP 6789 and the 6800-7300 range.
pub fn dissect_ceph(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if looks_like_ceph(payload) {
        format!(
            "Ceph banner — messenger v1 ({})",
            super::bytes(payload.len() as u64)
        )
    } else {
        match payload.first().copied().and_then(tag_name) {
            Some(tag) => format!("Ceph {tag}"),
            None => format!("Ceph ({})", super::bytes(payload.len() as u64)),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ceph,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_opens_a_connection() {
        let mut p = BANNER.to_vec();
        p.extend_from_slice(&[0u8; 40]); // the entity address that follows
        let r = dissect_ceph(None, None, 40000, 6789, &p);
        assert_eq!(r.protocol, Protocol::Ceph);
        assert_eq!(r.summary, "Ceph banner — messenger v1 (49 bytes)");
    }

    #[test]
    fn message_and_keepalive_tags_are_named() {
        let r = dissect_ceph(None, None, 1, 6789, &[7, 0, 0, 0]);
        assert_eq!(r.summary, "Ceph MSG");
        let r = dissect_ceph(None, None, 1, 6789, &[14, 0, 0, 0]);
        assert_eq!(r.summary, "Ceph KEEPALIVE2");
    }

    #[test]
    fn session_failures_are_named() {
        assert_eq!(
            dissect_ceph(None, None, 1, 6789, &[2]).summary,
            "Ceph RESETSESSION"
        );
        assert_eq!(
            dissect_ceph(None, None, 1, 6789, &[11]).summary,
            "Ceph BADAUTHORIZER"
        );
    }

    /// The banner is the only signal strong enough to claim a connection; a
    /// bare tag byte would match almost anything.
    #[test]
    fn only_the_banner_identifies_ceph() {
        assert!(looks_like_ceph(BANNER));
        assert!(!looks_like_ceph(b"ceph v0"));
        assert!(!looks_like_ceph(&[7, 0, 0, 0]));
        assert!(!looks_like_ceph(b"GET / HTTP/1.1"));
        assert!(!looks_like_ceph(&[]));
    }

    #[test]
    fn unknown_tag_reports_the_size() {
        let r = dissect_ceph(None, None, 1, 6789, &[99, 0, 0, 0]);
        assert_eq!(r.summary, "Ceph (4 bytes)");
    }

    #[test]
    fn empty_input_does_not_panic() {
        let r = dissect_ceph(None, None, 1, 6789, &[]);
        assert_eq!(r.summary, "Ceph (0 bytes)");
    }
}
