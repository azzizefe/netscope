// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DEC Maintenance Operation Protocol (MOP, EtherType 0x6002) frame.
pub fn dissect_dec_mop(payload: &[u8]) -> DissectedResult {
    let summary = if !payload.is_empty() {
        let code = payload[0];
        let name = match code {
            0x02 => "Dump Request",
            0x04 => "Memory Dump",
            0x06 => "Load Request",
            0x08 => "Memory Load",
            0x0A => "Parameter Read",
            0x0C => "System ID",
            0x14 => "Loopback",
            _ => "Message",
        };
        format!("DEC MOP {name}")
    } else {
        format!("DEC MOP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::DecMop,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_mop_system_id() {
        let payload = vec![0x0C, 0x00, 0x01];
        let r = dissect_dec_mop(&payload);
        assert_eq!(r.protocol, Protocol::DecMop);
        assert_eq!(r.summary, "DEC MOP System ID");
    }
}
