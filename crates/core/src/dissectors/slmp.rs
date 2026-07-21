// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SLMP / MELSEC command codes (Mitsubishi SLMP reference SH-080956).
fn command_name(cmd: u16) -> Option<&'static str> {
    Some(match cmd {
        0x0401 => "Read",
        0x1401 => "Write",
        0x0403 => "Read Random",
        0x1402 => "Write Random",
        0x0406 => "Read Block",
        0x1406 => "Write Block",
        0x1601 => "Entry Monitor Device",
        0x0801 => "Execute Monitor",
        0x1001 => "Remote Run",
        0x1002 => "Remote Stop",
        0x1003 => "Remote Pause",
        0x1005 => "Remote Latch Clear",
        0x1006 => "Remote Reset",
        0x0101 => "Read CPU Model",
        0x0114 => "Self Test",
        0x1810 => "Read Directory/File",
        0x1811 => "Search Directory/File",
        0x1820 => "New File",
        0x1822 => "Delete File",
        0x1824 => "Copy File",
        0x0613 => "Read Type Name",
        0x3070 => "Password Unlock",
        0x3071 => "Password Lock",
        _ => return None,
    })
}

/// Subheaders that open a frame (SH-080956 §2). The 3E frame is the common
/// binary form; 4E adds a serial number for matching requests to responses.
const SUBHEADER_3E_REQUEST: u16 = 0x5000;
const SUBHEADER_3E_RESPONSE: u16 = 0xD000;
const SUBHEADER_4E_REQUEST: u16 = 0x5400;
const SUBHEADER_4E_RESPONSE: u16 = 0xD400;

/// Dissect an SLMP / MELSEC message — Mitsubishi's PLC protocol, on TCP or UDP
/// 5007 (Mitsubishi SLMP reference SH-080956).
///
/// Like most fieldbus protocols it has no authentication: a Remote Stop is
/// obeyed because it arrived, not because the sender proved anything.
pub fn dissect_slmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("SLMP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Slmp,
        summary,
    }
}

pub(crate) fn parse(payload: &[u8]) -> Option<String> {
    let subheader = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    // The 4E frame inserts a two-byte serial and a two-byte reserved field
    // before the network fields, shifting everything that follows.
    let (is_response, extra) = match subheader {
        SUBHEADER_3E_REQUEST => (false, 0),
        SUBHEADER_3E_RESPONSE => (true, 0),
        SUBHEADER_4E_REQUEST => (false, 4),
        SUBHEADER_4E_RESPONSE => (true, 4),
        _ => return None,
    };
    // After the subheader: network number, station, module id (2), multidrop,
    // then a data length and a monitoring timer, then the command.
    let network = *payload.get(2 + extra)?;
    let station = *payload.get(3 + extra)?;

    if is_response {
        // A response carries a completion code where the request has its command.
        let code_at = 9 + extra;
        let code = u16::from_le_bytes([*payload.get(code_at)?, *payload.get(code_at + 1)?]);
        return Some(if code == 0 {
            format!("SLMP response OK — station {network}.{station}")
        } else {
            format!("SLMP response error 0x{code:04x} — station {network}.{station}")
        });
    }

    // Request: the command sits after the completion-code slot and the timer.
    let cmd_at = 11 + extra;
    let cmd = u16::from_le_bytes([*payload.get(cmd_at)?, *payload.get(cmd_at + 1)?]);
    Some(match command_name(cmd) {
        Some(name) => format!("SLMP {name} — station {network}.{station}"),
        None => format!("SLMP command 0x{cmd:04x} — station {network}.{station}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 3E-frame request carrying `cmd`.
    fn request(network: u8, station: u8, cmd: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&SUBHEADER_3E_REQUEST.to_be_bytes());
        p.push(network);
        p.push(station);
        p.extend_from_slice(&[0x00, 0x00]); // module id
        p.push(0x00); // multidrop station
        p.extend_from_slice(&[0x00, 0x00]); // request data length
        p.extend_from_slice(&[0x10, 0x00]); // monitoring timer
        p.extend_from_slice(&cmd.to_le_bytes());
        p
    }

    #[test]
    fn read_command() {
        let r = dissect_slmp(None, None, 40000, 5007, &request(0, 255, 0x0401));
        assert_eq!(r.protocol, Protocol::Slmp);
        assert_eq!(r.summary, "SLMP Read — station 0.255");
    }

    /// The commands that change plant state.
    #[test]
    fn remote_stop_and_reset_are_named() {
        let r = dissect_slmp(None, None, 1, 5007, &request(0, 255, 0x1002));
        assert_eq!(r.summary, "SLMP Remote Stop — station 0.255");
        let r = dissect_slmp(None, None, 1, 5007, &request(0, 255, 0x1006));
        assert_eq!(r.summary, "SLMP Remote Reset — station 0.255");
    }

    #[test]
    fn response_reports_its_completion_code() {
        let mut p = Vec::new();
        p.extend_from_slice(&SUBHEADER_3E_RESPONSE.to_be_bytes());
        p.extend_from_slice(&[0x00, 0xFF, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&[0x00, 0x00]); // response data length
        p.extend_from_slice(&[0x00, 0x00]); // completion code: success
        let r = dissect_slmp(None, None, 5007, 40000, &p);
        assert_eq!(r.summary, "SLMP response OK — station 0.255");

        let mut bad = p.clone();
        bad[9] = 0x55;
        bad[10] = 0xC0;
        let r = dissect_slmp(None, None, 5007, 40000, &bad);
        assert_eq!(r.summary, "SLMP response error 0xc055 — station 0.255");
    }

    /// The 4E frame shifts every field by four bytes; parsing it as 3E would
    /// read the serial number as a command.
    #[test]
    fn four_e_frame_offsets_are_honoured() {
        let mut p = Vec::new();
        p.extend_from_slice(&SUBHEADER_4E_REQUEST.to_be_bytes());
        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // serial + reserved
        p.push(0x00); // network
        p.push(0xFF); // station
        p.extend_from_slice(&[0x00, 0x00, 0x00]); // module id + multidrop
        p.extend_from_slice(&[0x00, 0x00]); // data length
        p.extend_from_slice(&[0x10, 0x00]); // timer
        p.extend_from_slice(&0x0401u16.to_le_bytes());
        let r = dissect_slmp(None, None, 40000, 5007, &p);
        assert_eq!(r.summary, "SLMP Read — station 0.255");
    }

    #[test]
    fn foreign_subheader_is_not_claimed() {
        let r = dissect_slmp(None, None, 1, 5007, &[0xFF, 0xFF, 0x00, 0x00]);
        assert_eq!(r.summary, "SLMP (4 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_slmp(None, None, 1, 5007, &[0x50, 0x00]);
        assert_eq!(r.summary, "SLMP (2 bytes)");
    }
}
