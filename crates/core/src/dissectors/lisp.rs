// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Flags, nonce or map version, then the instance id.
const DATA_HEADER: usize = 8;

/// Dissect a LISP message (UDP 4342 control / 4341 data) — Locator/ID
/// Separation Protocol, which splits "who a host is" from "where it currently
/// is" so endpoints can move without renumbering. The control plane's message
/// type is the top nibble of byte 0 (RFC 9300).
pub fn dissect_lisp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let is_control = src_port == 4342 || dst_port == 4342;
    // A data packet carries an inner IP packet directly after the eight-byte
    // header, and that packet is the traffic the overlay exists to move.
    if !is_control {
        if let Some(inner) = payload.get(DATA_HEADER..) {
            let ethertype = match inner.first().map(|b| b >> 4) {
                Some(4) => Some(0x0800u16),
                Some(6) => Some(0x86DDu16),
                _ => None,
            };
            if let Some(et) = ethertype {
                let mut r = super::dispatch_l3(et, inner, 0);
                r.summary = format!("LISP · {}", r.summary);
                r.src_port = Some(src_port);
                r.dst_port = Some(dst_port);
                return r;
            }
        }
    }

    let summary = if is_control {
        match payload.first() {
            Some(&b) => {
                let name = match b >> 4 {
                    1 => "Map-Request",
                    2 => "Map-Reply",
                    3 => "Map-Register",
                    4 => "Map-Notify",
                    8 => "Encapsulated Control Message",
                    _ => "control message",
                };
                format!("LISP {name}")
            }
            None => "LISP control (empty)".to_string(),
        }
    } else {
        format!(
            "LISP data — encapsulated packet ({})",
            super::bytes(payload.len() as u64)
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lisp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_register() {
        let r = dissect_lisp(None, None, 40000, 4342, &[0x30, 0x00, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Lisp);
        assert_eq!(r.summary, "LISP Map-Register");
    }

    #[test]
    fn data_plane() {
        let r = dissect_lisp(None, None, 40000, 4341, &[0x00; 8]);
        assert!(r.summary.contains("encapsulated"), "{}", r.summary);
    }
}
