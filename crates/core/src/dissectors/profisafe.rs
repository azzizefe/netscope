// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;
use super::DissectedResult;

/// Heuristically check if a cyclic PROFINET payload looks like PROFIsafe.
pub(crate) fn looks_like_profisafe(payload: &[u8]) -> bool {
    if payload.len() < 6 || payload.len() > 32 {
        return false;
    }
    let crc_len = if payload.len() <= 16 { 3 } else { 4 };
    let sb_index = payload.len() - 1 - crc_len;
    let sb = payload[sb_index];
    sb & 0x80 == 0
}

/// Dissect a PROFIsafe SPDU (Safety Protocol Data Unit).
///
/// A PROFIsafe SPDU contains application safety data, a Status/Control Byte,
/// and a 3-byte or 4-byte CRC.
pub fn dissect_profisafe(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Profisafe,
        summary: String::new(),
    };

    if payload.len() < 5 {
        return DissectedResult {
            summary: format!(
                "PROFIsafe ({})",
                super::bytes(payload.len() as u64)
            ),
            ..base
        };
    }

    // Determine CRC length (3 or 4 bytes). In PROFIsafe V2 it is 3 bytes (if F-Data <= 12 bytes) or 4 bytes.
    // Let's assume 3 bytes if payload length is small, else 4 bytes.
    let crc_len = if payload.len() <= 16 { 3 } else { 4 };
    let safety_data_len = payload.len() - 1 - crc_len;
    let sb_index = safety_data_len;
    let sb = payload[sb_index];

    // Status/Control byte bit flags
    let ipar_ok = sb & 0x01 != 0;
    let ack_req = sb & 0x02 != 0;
    let _cons_nr = sb & 0x04 != 0;
    let wd_to = sb & 0x08 != 0;
    let fv_active = sb & 0x10 != 0;
    let toggle = sb & 0x20 != 0;
    let fault = sb & 0x40 != 0;

    let mut flags = Vec::new();
    if fv_active {
        flags.push("Fail-Safe Active");
    }
    if wd_to {
        flags.push("Watchdog Timeout");
    }
    if fault {
        flags.push("System Fault");
    }
    if ipar_ok {
        flags.push("iPar OK");
    }
    if ack_req {
        flags.push("Ack Req");
    }

    let flags_str = if flags.is_empty() {
        "Normal".to_string()
    } else {
        flags.join("|")
    };

    let summary = format!(
        "PROFIsafe — Safety Data: {}, Status/Control: 0x{:02x} ({}), Toggle: {}",
        super::bytes(safety_data_len as u64),
        sb,
        flags_str,
        if toggle { "1" } else { "0" }
    );

    DissectedResult { summary, ..base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_profisafe_normal() {
        // 2 bytes safety data, status byte (0x20 -> toggle=1), 3 bytes CRC
        let payload = vec![0x01, 0x02, 0x20, 0xAA, 0xBB, 0xCC];
        let r = dissect_profisafe(&payload);
        assert_eq!(r.protocol, Protocol::Profisafe);
        assert_eq!(
            r.summary,
            "PROFIsafe — Safety Data: 2 bytes, Status/Control: 0x20 (Normal), Toggle: 1"
        );
    }
}
