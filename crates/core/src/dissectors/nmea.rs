// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check: an NMEA sentence begins with `$` or `!`. Cheap insurance
/// against claiming an unrelated flow that merely used port 10110.
pub fn looks_like_nmea(p: &[u8]) -> bool {
    matches!(p.first(), Some(b'$') | Some(b'!'))
}

/// Dissect an NMEA 0183 stream (TCP 10110) — the sentence format GPS receivers
/// and marine instruments emit. A sentence starts with `$` (or `!` for
/// encapsulated AIS) and a five-character talker + sentence identifier.
pub fn dissect_nmea(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = match line.chars().next() {
        Some('$') | Some('!') => {
            let id: String = line.chars().skip(1).take(5).collect();
            let what = match &id[id.len().min(2)..] {
                "GGA" => " — position fix",
                "RMC" => " — recommended minimum data",
                "GSV" => " — satellites in view",
                "VTG" => " — course and speed",
                "VDM" => " — AIS vessel report",
                _ => "",
            };
            format!("NMEA {id}{what}")
        }
        _ => format!("NMEA stream ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nmea,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_fix() {
        let r = dissect_nmea(None, None, 40000, 10110, b"$GPGGA,123519,4807.038,N*47\r\n");
        assert_eq!(r.protocol, Protocol::Nmea);
        assert!(r.summary.contains("position fix"), "{}", r.summary);
    }

    #[test]
    fn ais_sentence() {
        let r = dissect_nmea(None, None, 40000, 10110, b"!AIVDM,1,1,,A,15M67F*7B\r\n");
        assert!(r.summary.contains("AIS"), "{}", r.summary);
    }
}
