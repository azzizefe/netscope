// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// AVDECC Subtype / Message Types (IEEE 1722.1 Audio Video Discovery, Enumeration, Control).
fn avdecc_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        0x6E | 0xFA => "ADP (Discovery)",
        0x6F | 0xFB => "AECP (Control)",
        0x70 | 0xFC => "ACMP (Connection Management)",
        0x7F | 0xFE => "MAAP",
        _ => "AVDECC Control",
    }
}

/// ADP Message Types (IEEE 1722.1 Clause 6.2).
fn adp_message_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x00 => "ENTITY_AVAILABLE",
        0x01 => "ENTITY_DEPARTING",
        0x02 => "ENTITY_DISCOVER",
        _ => "ADP Reserved",
    }
}

/// AECP Message Types (IEEE 1722.1 Clause 9.2).
fn aecp_message_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x00 => "AEM_COMMAND",
        0x01 => "AEM_RESPONSE",
        0x02 => "ADDRESS_ACCESS_COMMAND",
        0x03 => "ADDRESS_ACCESS_RESPONSE",
        0x04 => "AVC_COMMAND",
        0x05 => "AVC_RESPONSE",
        0x0E => "VENDOR_UNIQUE_COMMAND",
        0x0F => "VENDOR_UNIQUE_RESPONSE",
        _ => "AECP Reserved",
    }
}

/// Dissect an AVDECC (IEEE 1722.1) control message.
pub fn dissect_avdecc(payload: &[u8]) -> DissectedResult {
    let summary = if payload.is_empty() {
        "AVDECC (empty)".to_string()
    } else {
        let subtype = payload[0];
        let sub_name = avdecc_subtype_name(subtype);

        if (subtype == 0x6E || subtype == 0xFA) && payload.len() >= 2 {
            let msg_type = payload[1] & 0x0F;
            let msg_desc = adp_message_type_name(msg_type);
            format!("AVDECC {sub_name} — {msg_desc}")
        } else if (subtype == 0x6F || subtype == 0xFB) && payload.len() >= 2 {
            let msg_type = payload[1] & 0x0F;
            let msg_desc = aecp_message_type_name(msg_type);
            format!("AVDECC {sub_name} — {msg_desc}")
        } else {
            format!("AVDECC {sub_name}")
        }
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Avdecc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avdecc_adp_discovery() {
        // Subtype 0xFA (ADP), Message Type 0x00 (ENTITY_AVAILABLE)
        let payload = vec![0xFA, 0x00, 0x00, 0x00];
        let res = dissect_avdecc(&payload);
        assert_eq!(res.protocol, Protocol::Avdecc);
        assert!(res.summary.contains("ADP (Discovery)"));
        assert!(res.summary.contains("ENTITY_AVAILABLE"));
    }

    #[test]
    fn test_avdecc_aecp_command() {
        // Subtype 0xFB (AECP), Message Type 0x00 (AEM_COMMAND)
        let payload = vec![0xFB, 0x00, 0x00, 0x00];
        let res = dissect_avdecc(&payload);
        assert_eq!(res.protocol, Protocol::Avdecc);
        assert!(res.summary.contains("AECP (Control)"));
        assert!(res.summary.contains("AEM_COMMAND"));
    }
}
