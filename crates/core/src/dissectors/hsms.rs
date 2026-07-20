// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// HSMS session control messages (SEMI E37 §8.3). These manage the link itself
/// rather than carrying equipment data.
fn control_name(stype: u8) -> Option<&'static str> {
    Some(match stype {
        1 => "Select.req",
        2 => "Select.rsp",
        3 => "Deselect.req",
        4 => "Deselect.rsp",
        5 => "Linktest.req",
        6 => "Linktest.rsp",
        7 => "Reject.req",
        9 => "Separate.req",
        _ => return None,
    })
}

/// Well-known SECS-II stream/function pairs (SEMI E5). A capture from a
/// semiconductor fab is mostly these: the host asking the tool what it is,
/// the tool reporting events and alarms.
fn secs_name(stream: u8, function: u8) -> Option<&'static str> {
    Some(match (stream, function) {
        (1, 1) => "Are You There",
        (1, 2) => "On Line Data",
        (1, 3) => "Selected Equipment Status Request",
        (1, 4) => "Selected Equipment Status Data",
        (1, 13) => "Establish Communications Request",
        (1, 14) => "Establish Communications Acknowledge",
        (2, 13) => "Equipment Constant Request",
        (2, 14) => "Equipment Constant Data",
        (2, 15) => "New Equipment Constant Send",
        (2, 16) => "New Equipment Constant Acknowledge",
        (2, 31) => "Date and Time Set Request",
        (2, 33) => "Define Report",
        (2, 35) => "Link Event Report",
        (2, 37) => "Enable/Disable Event Report",
        (2, 41) => "Host Command Send",
        (2, 42) => "Host Command Acknowledge",
        (5, 1) => "Alarm Report Send",
        (5, 2) => "Alarm Report Acknowledge",
        (5, 3) => "Enable/Disable Alarm Send",
        (6, 11) => "Event Report Send",
        (6, 12) => "Event Report Acknowledge",
        (6, 15) => "Event Report Request",
        (7, 3) => "Process Program Send",
        (7, 5) => "Process Program Request",
        (7, 19) => "Current EPPD Request",
        (9, 1) => "Unrecognized Device ID",
        (9, 3) => "Unrecognized Stream Type",
        (9, 5) => "Unrecognized Function Type",
        (9, 7) => "Illegal Data",
        (10, 3) => "Terminal Display, Single",
        _ => return None,
    })
}

/// The HSMS message header is ten bytes after the four-byte length prefix
/// (SEMI E37 §8.2): device id, two type-dependent bytes, ptype, stype, then a
/// four-byte system id.
const LENGTH_PREFIX: usize = 4;
const HEADER: usize = 10;

/// stype 0 means the message carries SECS-II data rather than session control.
const STYPE_DATA: u8 = 0;
/// The high bit of the stream byte is the wait bit, not part of the number.
const WAIT_BIT: u8 = 0x80;

/// Dissect an HSMS message — the transport for SECS-II, which is how
/// semiconductor fab equipment talks to its host, on TCP 5000 (SEMI E37).
pub fn dissect_hsms(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("HSMS ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Hsms,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.len() < LENGTH_PREFIX + HEADER {
        return None;
    }
    let header = &payload[LENGTH_PREFIX..];
    let device = u16::from_be_bytes([header[0], header[1]]);
    let stype = header[5];

    if stype != STYPE_DATA {
        let name = control_name(stype)?;
        return Some(format!("HSMS {name}"));
    }
    // A data message puts the SECS-II stream and function in the two
    // type-dependent bytes, with the stream's high bit used as the wait flag.
    let stream = header[2] & !WAIT_BIT;
    let function = header[3];
    Some(match secs_name(stream, function) {
        Some(name) => format!("HSMS S{stream}F{function} {name} — device {device}"),
        None => format!("HSMS S{stream}F{function} — device {device}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an HSMS message: length prefix, then the ten-byte header.
    fn hsms(device: u16, b2: u8, b3: u8, stype: u8) -> Vec<u8> {
        let mut p = 10u32.to_be_bytes().to_vec();
        p.extend_from_slice(&device.to_be_bytes());
        p.push(b2);
        p.push(b3);
        p.push(0); // ptype: SECS-II
        p.push(stype);
        p.extend_from_slice(&1u32.to_be_bytes()); // system bytes
        p
    }

    #[test]
    fn linktest_is_session_control() {
        let r = dissect_hsms(None, None, 40000, 5000, &hsms(0, 0, 0, 5));
        assert_eq!(r.protocol, Protocol::Hsms);
        assert_eq!(r.summary, "HSMS Linktest.req");
    }

    #[test]
    fn data_message_names_the_secs_function() {
        // S1F1 "Are You There", with the wait bit set.
        let r = dissect_hsms(None, None, 40000, 5000, &hsms(1, 0x81, 1, 0));
        assert_eq!(r.summary, "HSMS S1F1 Are You There — device 1");
    }

    /// The wait bit shares a byte with the stream number; leaving it in would
    /// report stream 129 instead of stream 1.
    #[test]
    fn wait_bit_is_masked_off_the_stream() {
        let with_wait = dissect_hsms(None, None, 1, 5000, &hsms(1, 0x85, 1, 0));
        let without = dissect_hsms(None, None, 1, 5000, &hsms(1, 0x05, 1, 0));
        assert_eq!(with_wait.summary, without.summary);
        assert!(with_wait.summary.starts_with("HSMS S5F1"));
    }

    #[test]
    fn alarm_report_is_named() {
        let r = dissect_hsms(None, None, 1, 5000, &hsms(1, 0x85, 1, 0));
        assert_eq!(r.summary, "HSMS S5F1 Alarm Report Send — device 1");
    }

    /// A stream/function pair we don't have a name for still identifies itself
    /// by number, which is how SECS-II messages are referred to anyway.
    #[test]
    fn unknown_function_still_reports_stream_and_function() {
        let r = dissect_hsms(None, None, 1, 5000, &hsms(3, 0x63, 99, 0));
        assert_eq!(r.summary, "HSMS S99F99 — device 3");
    }

    #[test]
    fn unknown_control_type_is_not_claimed() {
        let r = dissect_hsms(None, None, 1, 5000, &hsms(0, 0, 0, 42));
        assert_eq!(r.summary, "HSMS (14 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_hsms(None, None, 1, 5000, &[0x00, 0x00, 0x00, 0x0A]);
        assert_eq!(r.summary, "HSMS (4 bytes)");
    }
}
