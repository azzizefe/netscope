// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AVTP frame (EtherType 0x22F0) — IEEE 1722 Audio/Video Transport,
/// used in automotive Ethernet and pro AV to stream time-synced media. Byte 0
/// is the subtype.
pub fn dissect_avtp(payload: &[u8]) -> DissectedResult {
    if let Some(&s) = payload.first() {
        if matches!(s, 0x6E | 0x6F | 0x70 | 0xFA | 0xFB | 0xFC) {
            return super::avdecc::dissect_avdecc(payload);
        }
    }

    let summary = match payload.first() {
        Some(&s) => {
            let name = match s {
                0x00 => "IEC 61883/IIDC",
                0x02 => "MPEG-TS",
                0x03 => "Compressed Video (CVF)",
                0x22 => "AVTP Audio (AAF)",
                0x23 => "Clock Reference (CRF)",
                0xFE => "MAAP",
                _ => "stream",
            };
            format!("AVTP — {name}")
        }
        None => "AVTP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Avtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_stream() {
        let r = dissect_avtp(&[0x22, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Avtp);
        assert!(r.summary.contains("AAF"), "{}", r.summary);
    }
}
