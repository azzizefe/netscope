// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NTP message (UDP 123). The first byte packs Leap Indicator
/// (2 bits), Version (3 bits) and Mode (3 bits); byte 1 is the stratum.
pub fn dissect_ntp(
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
        protocol: Protocol::Ntp,
        summary,
    };

    if payload.is_empty() {
        return result("NTP (empty)".into());
    }

    let flags = payload[0];
    let version = (flags >> 3) & 0x07;
    let mode = flags & 0x07;
    let mode_name = ntp_mode_name(mode);

    // Modes 6 and 7 are not time synchronisation at all — they are the query
    // and remote-configuration interfaces, and they are where NTP's reflection
    // problem lives. A `monlist` request is six bytes and can be answered with
    // six hundred addresses, which is why it was the vector behind the large
    // amplification attacks. Naming these is the difference between "some NTP"
    // and "someone is testing this server as an amplifier".
    if let Some(detail) = control_detail(mode, payload) {
        return result(format!("NTP v{version} {detail}"));
    }

    let summary = match payload.get(1) {
        // Stratum is only meaningful for symmetric/client/server modes.
        Some(&stratum) if matches!(mode, 1..=5) => {
            format!("NTP v{version} {mode_name} (stratum {stratum})")
        }
        _ => format!("NTP v{version} {mode_name}"),
    };

    result(summary)
}

/// Describe a mode 6 control or mode 7 private message.
fn control_detail(mode: u8, payload: &[u8]) -> Option<String> {
    match mode {
        6 => {
            // Response, error and more bits, then a five-bit opcode.
            let byte = *payload.get(1)?;
            let is_response = byte & 0x80 != 0;
            let is_error = byte & 0x40 != 0;
            let opcode = byte & 0x1F;
            let name = control_opcode_name(opcode)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("opcode {opcode}"));
            Some(if is_error {
                format!("control {name} — refused")
            } else if is_response {
                format!("control {name} — response")
            } else {
                format!("control {name}")
            })
        }
        7 => {
            let is_response = *payload.first()? & 0x80 != 0;
            let request = *payload.get(3)?;
            let name = private_request_name(request)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("request {request}"));
            Some(if is_response {
                format!("private mode {name} — response")
            } else {
                format!("private mode {name}")
            })
        }
        _ => None,
    }
}

/// Mode 6 control opcodes. `read variables` and `read status` are what `ntpq`
/// uses, and are also the pair used to reflect traffic off a server.
fn control_opcode_name(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        1 => "read status",
        2 => "read variables",
        3 => "write variables",
        4 => "read clock variables",
        5 => "write clock variables",
        6 => "set trap",
        7 => "trap response",
        8 => "configure (remote configuration)",
        9 => "save configuration",
        10 => "read most-recently-used list (an amplification vector)",
        11 => "read ordered list",
        12 => "request nonce",
        _ => return None,
    })
}

/// Mode 7 request codes for the reference implementation. `monlist` is the one
/// that matters: it was the vector behind the 2013-14 reflection attacks and is
/// disabled on any server that has been patched since.
fn private_request_name(request: u8) -> Option<&'static str> {
    Some(match request {
        0 => "peer list",
        1 => "peer list summary",
        2 => "peer info",
        3 => "peer statistics",
        4 => "system info",
        5 => "system statistics",
        10 => "loop info",
        16 => "get restrict list",
        20 => "monitor getlist",
        42 => "monlist (a large amplification vector)",
        _ => return None,
    })
}

fn ntp_mode_name(mode: u8) -> &'static str {
    match mode {
        0 => "reserved",
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the first two NTP bytes from version, mode and stratum.
    fn ntp_bytes(version: u8, mode: u8, stratum: u8) -> Vec<u8> {
        let flags = (version << 3) | mode;
        let mut p = vec![flags, stratum];
        p.extend_from_slice(&[0u8; 46]); // rest of a 48-byte NTP packet
        p
    }

    #[test]
    fn client_request_labeled() {
        let pkt = ntp_bytes(4, 3, 0);
        let r = dissect_ntp(None, None, 51000, 123, &pkt);
        assert_eq!(r.protocol, Protocol::Ntp);
        assert_eq!(r.summary, "NTP v4 client (stratum 0)");
    }

    #[test]
    fn server_reply_labeled() {
        let pkt = ntp_bytes(4, 4, 2);
        let r = dissect_ntp(None, None, 123, 51000, &pkt);
        assert_eq!(r.summary, "NTP v4 server (stratum 2)");
    }

    #[test]
    fn empty_is_handled() {
        let r = dissect_ntp(None, None, 123, 123, &[]);
        assert_eq!(r.protocol, Protocol::Ntp);
        assert!(r.summary.contains("empty"));
    }

    /// A mode 7 private-mode message: response bit and version in byte 0, the
    /// request code in byte 3.
    fn private_mode(request: u8, response: bool) -> Vec<u8> {
        let mut p = vec![
            if response {
                0x80 | (2 << 3) | 7
            } else {
                (2 << 3) | 7
            },
            0x00,
            0x03,
            request,
        ];
        p.extend_from_slice(&[0u8; 40]);
        p
    }

    /// A mode 6 control message: version and mode in byte 0, flags and opcode
    /// in byte 1.
    fn control(opcode: u8, flags: u8) -> Vec<u8> {
        let mut p = vec![(4 << 3) | 6, flags | opcode];
        p.extend_from_slice(&[0u8; 10]);
        p
    }

    /// The reason this exists: a six-byte request that can be answered with six
    /// hundred addresses. Reading it as "NTP v2 private" hides an amplification
    /// probe among ordinary time traffic.
    #[test]
    fn monlist_is_named_as_an_amplification_vector() {
        let r = dissect_ntp(None, None, 51000, 123, &private_mode(42, false));
        assert_eq!(
            r.summary,
            "NTP v2 private mode monlist (a large amplification vector)"
        );
        assert!(dissect_ntp(None, None, 123, 51000, &private_mode(42, true))
            .summary
            .ends_with("— response"));
    }

    /// The other mode 7 queries are legitimate diagnostics and should read as
    /// what they are rather than all being flagged.
    #[test]
    fn ordinary_private_mode_queries_are_named_plainly() {
        assert!(dissect_ntp(None, None, 1, 123, &private_mode(0, false))
            .summary
            .contains("peer list"));
        assert!(dissect_ntp(None, None, 1, 123, &private_mode(4, false))
            .summary
            .contains("system info"));
    }

    /// Mode 6 is what `ntpq` speaks. Remote configuration is worth spotting
    /// because it changes the server rather than reading it.
    #[test]
    fn control_messages_are_named() {
        assert_eq!(
            dissect_ntp(None, None, 1, 123, &control(2, 0)).summary,
            "NTP v4 control read variables"
        );
        assert!(dissect_ntp(None, None, 1, 123, &control(8, 0))
            .summary
            .contains("remote configuration"));
        assert!(dissect_ntp(None, None, 1, 123, &control(10, 0))
            .summary
            .contains("amplification vector"));
    }

    /// The response and error bits share byte 1 with the opcode, so masking
    /// them off matters — otherwise a response to opcode 2 reads as opcode 130.
    #[test]
    fn the_flag_bits_are_masked_off_the_opcode() {
        assert_eq!(
            dissect_ntp(None, None, 123, 1, &control(2, 0x80)).summary,
            "NTP v4 control read variables — response"
        );
        assert_eq!(
            dissect_ntp(None, None, 123, 1, &control(2, 0xC0)).summary,
            "NTP v4 control read variables — refused"
        );
    }

    /// An unknown code keeps its number rather than being given the meaning of
    /// whichever entry was nearest.
    #[test]
    fn unknown_codes_keep_their_numbers() {
        assert!(dissect_ntp(None, None, 1, 123, &private_mode(99, false))
            .summary
            .contains("request 99"));
        assert!(dissect_ntp(None, None, 1, 123, &control(30, 0))
            .summary
            .contains("opcode 30"));
    }

    /// Ordinary time synchronisation must not be dragged through the control
    /// path, and a truncated control message must not panic.
    #[test]
    fn time_traffic_is_untouched_and_truncation_is_safe() {
        let r = dissect_ntp(None, None, 51000, 123, &ntp_bytes(4, 3, 0));
        assert_eq!(r.summary, "NTP v4 client (stratum 0)");
        assert!(dissect_ntp(None, None, 1, 123, &[(4 << 3) | 6])
            .summary
            .contains("control"));
        assert!(dissect_ntp(None, None, 1, 123, &[(2 << 3) | 7])
            .summary
            .contains("private"));
    }
}
