// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Pull a text TLV value out of the CDP body. TLVs are type(2) length(2) value,
/// where length counts the whole TLV.
fn text_tlv(body: &[u8], want: u16) -> Option<String> {
    let mut i = 4; // skip version, TTL and checksum
    while i + 4 <= body.len() {
        let t = u16::from_be_bytes([body[i], body[i + 1]]);
        let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        if len < 4 || i + len > body.len() {
            return None;
        }
        if t == want {
            let v = String::from_utf8_lossy(&body[i + 4..i + len]);
            return Some(v.trim().to_string());
        }
        i += len;
    }
    None
}

/// Dissect a CDP frame (LLC/SNAP, Cisco OUI, PID 0x2000) — Cisco Discovery
/// Protocol, which announces a device's identity, port and platform to its
/// directly-connected neighbours. The Cisco counterpart to LLDP.
pub fn dissect_cdp(body: &[u8]) -> DissectedResult {
    let device = text_tlv(body, 0x0001);
    let port = text_tlv(body, 0x0003);
    let summary = match (device, port) {
        (Some(d), Some(p)) => format!(
            "CDP — {} port {}",
            super::truncate(&d, 32),
            super::truncate(&p, 24)
        ),
        (Some(d), None) => format!("CDP — {}", super::truncate(&d, 32)),
        _ => format!("CDP announcement ({} bytes)", body.len()),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Cdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_and_port() {
        let mut b = vec![0x02, 0xB4, 0x00, 0x00]; // version, TTL, checksum
        // TLV length counts the 4-byte header too: 4 + 7 = 11.
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x0b]); // Device ID TLV
        b.extend_from_slice(b"sw-core");
        b.extend_from_slice(&[0x00, 0x03, 0x00, 0x09]); // Port ID TLV, len 9
        b.extend_from_slice(b"Gi0/1");
        let r = dissect_cdp(&b);
        assert_eq!(r.protocol, Protocol::Cdp);
        assert_eq!(r.summary, "CDP — sw-core port Gi0/1");
    }
}
