// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DNP3 message (TCP/UDP 20000).
///
/// DNP3 (Distributed Network Protocol) runs electricity grids and water
/// utilities. Every link-layer frame starts with the sync bytes 0x05 0x64,
/// then length(1), control(1), destination(2, LE) and source(2, LE). The
/// control byte's low nibble is the function; its DIR/PRM bits say which way
/// the frame flows. We surface the addresses and the link function — enough to
/// follow a master/outstation conversation in an OT capture.
pub fn dissect_dnp3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dnp3,
        summary,
    };

    if payload.len() < 10 || payload[0] != 0x05 || payload[1] != 0x64 {
        return result("DNP3 (partial or non-sync)".into());
    }

    let control = payload[3];
    let dest = u16::from_le_bytes([payload[4], payload[5]]);
    let src = u16::from_le_bytes([payload[6], payload[7]]);
    let is_master = control & 0x40 != 0; // PRM: primary message from master
    let func = control & 0x0f;
    let func_name = if is_master {
        primary_function(func)
    } else {
        secondary_function(func)
    };

    result(format!("DNP3 {func_name} — {src} → {dest}"))
}

/// Sync-byte signature, used to accept DNP3 on relocated ports.
pub fn looks_like_dnp3(payload: &[u8]) -> bool {
    payload.len() >= 10 && payload[0] == 0x05 && payload[1] == 0x64
}

fn primary_function(f: u8) -> &'static str {
    match f {
        0 => "RESET_LINK",
        1 => "RESET_USER_PROCESS",
        2 => "TEST_LINK",
        3 => "CONFIRMED_USER_DATA",
        4 => "UNCONFIRMED_USER_DATA",
        9 => "REQUEST_LINK_STATUS",
        _ => "primary",
    }
}

fn secondary_function(f: u8) -> &'static str {
    match f {
        0 => "ACK",
        1 => "NACK",
        11 => "LINK_STATUS",
        14 => "NOT_SUPPORTED",
        _ => "secondary",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(control: u8, dest: u16, src: u16) -> Vec<u8> {
        let mut p = vec![0x05, 0x64, 0x05, control];
        p.extend_from_slice(&dest.to_le_bytes());
        p.extend_from_slice(&src.to_le_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // CRC
        p
    }

    #[test]
    fn unconfirmed_user_data_from_master() {
        // PRM set (0x40) + function 4 = 0x44
        let p = frame(0x44, 1024, 1);
        let r = dissect_dnp3(None, None, 50000, 20000, &p);
        assert_eq!(r.protocol, Protocol::Dnp3);
        assert_eq!(r.summary, "DNP3 UNCONFIRMED_USER_DATA — 1 → 1024");
    }

    #[test]
    fn link_status_from_outstation() {
        // PRM clear + function 11 = 0x0b
        let p = frame(0x0b, 1, 1024);
        let r = dissect_dnp3(None, None, 20000, 50000, &p);
        assert_eq!(r.summary, "DNP3 LINK_STATUS — 1024 → 1");
    }

    #[test]
    fn non_sync_is_safe() {
        let r = dissect_dnp3(None, None, 20000, 50000, &[0; 12]);
        assert!(r.summary.contains("non-sync"));
    }
}
