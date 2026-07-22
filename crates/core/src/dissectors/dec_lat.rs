// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DEC Local Area Transport (LAT, EtherType 0x6004) frame.
pub fn dissect_dec_lat(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let msg_type = payload[0] >> 2;
        let name = match msg_type {
            0x00 => "Run Message",
            0x02 => "Connect Message",
            0x04 => "Disconnect Message",
            0x0A => "Service Announcement",
            _ => "Message",
        };
        format!("DEC LAT {name}")
    } else {
        format!("DEC LAT ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::DecLat,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_lat_service_announcement() {
        let payload = vec![0x28, 0x00];
        let r = dissect_dec_lat(&payload);
        assert_eq!(r.protocol, Protocol::DecLat);
        assert_eq!(r.summary, "DEC LAT Service Announcement");
    }
}
