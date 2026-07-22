// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a NetBEUI (NetBIOS Frame Protocol / NBF, LLC SAP 0xF0) frame.
pub fn dissect_netbeui(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let cmd = payload[3];
        let cmd_name = match cmd {
            0x00 => "Add Name Query",
            0x01 => "Add Name Response",
            0x02 => "Delete Name",
            0x03 => "Data First Middle",
            0x08 => "Data Only",
            0x09 => "Status Query",
            0x0A => "Status Response",
            0x0D => "Session Alive",
            0x0E => "Session Initialize",
            0x0F => "Session Confirm",
            0x14 => "Name Query",
            0x15 => "Name Recognized",
            _ => "Frame",
        };
        format!("NetBEUI {cmd_name}")
    } else {
        format!("NetBEUI ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::NetBeui,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbeui_session_init() {
        let payload = vec![0x0E, 0x00, 0xEF, 0x0E];
        let r = dissect_netbeui(&payload);
        assert_eq!(r.protocol, Protocol::NetBeui);
        assert_eq!(r.summary, "NetBEUI Session Initialize");
    }
}
