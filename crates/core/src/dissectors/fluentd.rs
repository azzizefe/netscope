// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Fluentd forward message (TCP 24224) — the log-collector protocol
/// applications and agents use to ship events. Each message is a MessagePack
/// array whose first byte encodes the array length.
pub fn dissect_fluentd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        // MessagePack fixarray of 2..4 elements: [tag, time, record, option].
        Some(&b @ 0x92..=0x94) => {
            format!("Fluentd forward ({} fields, msgpack)", b & 0x0f)
        }
        Some(0xdc) | Some(0xdd) => "Fluentd forward (msgpack array)".to_string(),
        _ => format!("Fluentd forward ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fluentd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_message() {
        let r = dissect_fluentd(None, None, 40000, 24224, &[0x93, 0xa3, b'a', b'p', b'p']);
        assert_eq!(r.protocol, Protocol::Fluentd);
        assert_eq!(r.summary, "Fluentd forward (3 fields, msgpack)");
    }
}
