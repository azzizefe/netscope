// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// NMEA 2000 Parameter Group Number (PGN) descriptions.
fn nmea2000_pgn_name(pgn: u32) -> &'static str {
    match pgn {
        126992 => "System Time",
        127250 => "Vessel Heading",
        127251 => "Rate of Turn",
        127257 => "Attitude (Roll/Pitch/Yaw)",
        127488 => "Engine Parameters, Rapid Update",
        127489 => "Engine Parameters, Dynamic",
        128259 => "Speed Through Water",
        128267 => "Water Depth",
        129025 => "Position, Rapid Update (Lat/Lon)",
        129026 => "COG & SOG, Rapid Update",
        129029 => "GNSS Position Data",
        130306 => "Wind Data (Speed & Angle)",
        130310 => "Environmental Parameters",
        130312 => "Temperature",
        _ => "Custom NMEA 2000 PGN",
    }
}

/// Dissect an NMEA 2000 (N2K) CAN message or gateway encapsulation.
pub fn dissect_nmea2000(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("NMEA 2000 ({})", super::bytes(payload.len() as u64))
    } else {
        // Can be 29-bit CAN ID or 3-byte PGN header
        let pgn = if payload.len() >= 4 && (payload[0] & 0x80) != 0 {
            // Extended 29-bit CAN ID format: Priority (3), PGN (18), SrcAddr (8)
            let raw_id = u32::from_be_bytes([payload[0] & 0x1F, payload[1], payload[2], payload[3]]);
            (raw_id >> 8) & 0x03FFFF
        } else {
            // Direct 3-byte PGN header (little-endian / big-endian gateway framing)
            u32::from_le_bytes([payload[0], payload[1], payload[2], 0])
        };

        let pgn_desc = nmea2000_pgn_name(pgn);
        let src_addr = if payload.len() >= 4 { payload[3] } else { 0 };

        format!("NMEA 2000 PGN {pgn} ({pgn_desc}) — src node {src_addr}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nmea2000,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmea2000_position_pgn() {
        // PGN 129025 (0x01F801 = Position, Rapid Update), src node 15
        let payload = vec![0x01, 0xF8, 0x01, 0x0F, 0x00, 0x00];
        let res = dissect_nmea2000(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nmea2000);
        assert!(res.summary.contains("PGN 129025"));
        assert!(res.summary.contains("Position, Rapid Update"));
        assert!(res.summary.contains("src node 15"));
    }

    #[test]
    fn test_nmea2000_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_nmea2000(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nmea2000);
        assert!(res.summary.contains("NMEA 2000 (2 bytes)"));
    }
}
