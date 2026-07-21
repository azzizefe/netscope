// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Art-Net and sACN — stage lighting carried over Ethernet.
//!
//! Theatrical lighting is controlled by DMX512: 512 channels of one byte each,
//! grouped into a "universe". These two protocols carry universes over IP so a
//! console can drive a rig without a cable per dimmer. Art-Net is the older,
//! informal one; sACN (ANSI E1.31) is the standardised answer.
//!
//! One module because they solve exactly the same problem and the diagnosis is
//! identical in both — but their formats are not, so each is parsed separately.
//!
//! The two things worth reading are the sequence number and the priority.
//!
//! Every packet for a universe carries an incrementing sequence, so a gap means
//! frames were lost and the rig visibly stutters. And sACN lets several sources
//! send the same universe at different priorities: the receiver obeys the
//! highest. Two consoles at the same priority is the classic failure — the
//! fixtures flicker between two states at packet rate, and each console shows a
//! perfectly correct output. Nothing but the wire shows both senders.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Art-Net's fixed identifier, including its terminator.
const ARTNET_ID: &[u8] = b"Art-Net\0";
/// Identifier, then the opcode.
const ARTNET_HEADER: usize = 10;

/// sACN nests its framing layer inside an ACN root layer of this size.
const ACN_ROOT_LEN: usize = 38;
/// The ACN identifier sits four bytes into the root layer.
const ACN_ID_OFFSET: usize = 4;
const ACN_ID: &[u8] = b"ASC-E1.17\0\0\0";

/// Offsets inside the sACN framing layer, from the start of the packet.
const SACN_PRIORITY: usize = ACN_ROOT_LEN + 2 + 4 + 64;
const SACN_SEQUENCE: usize = SACN_PRIORITY + 3;
const SACN_UNIVERSE: usize = SACN_SEQUENCE + 2;
/// The name a console gives itself, ahead of the priority.
const SACN_SOURCE_NAME: usize = ACN_ROOT_LEN + 2 + 4;

/// What an Art-Net packet is for. The opcode is little-endian, unlike almost
/// everything else on the wire.
fn artnet_opcode(opcode: u16) -> Option<&'static str> {
    Some(match opcode {
        0x2000 => "Poll",
        0x2100 => "PollReply",
        0x2300 => "diagnostic data",
        0x2400 => "command",
        0x5000 => "DMX",
        0x5100 => "non-zero-start DMX",
        0x5200 => "sync",
        0x6000 => "address programming",
        0x7000 => "input configuration",
        0x8000 => "TOD request",
        0xF000 => "firmware upload",
        _ => return None,
    })
}

/// Whether a payload is Art-Net.
pub(crate) fn looks_like_artnet(payload: &[u8]) -> bool {
    payload.starts_with(ARTNET_ID)
}

/// Whether a payload is sACN, by the ACN identifier and preamble.
pub(crate) fn looks_like_sacn(payload: &[u8]) -> bool {
    payload.get(..2) == Some(&[0x00, 0x10])
        && payload.get(ACN_ID_OFFSET..ACN_ID_OFFSET + ACN_ID.len()) == Some(ACN_ID)
}

/// Dissect an Art-Net packet.
pub fn dissect_artnet(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Artnet,
        summary: describe_artnet(payload),
    }
}

/// Dissect an sACN (ANSI E1.31) packet.
pub fn dissect_sacn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sacn,
        summary: describe_sacn(payload),
    }
}

fn describe_artnet(payload: &[u8]) -> String {
    // The port is assigned, but the identifier is a fixed string and checking
    // it costs nothing — something else squatting on 6454 should not be
    // reported as a lighting command.
    if !looks_like_artnet(payload) {
        return "Art-Net (no identifier)".to_string();
    }
    let Some(head) = payload.get(..ARTNET_HEADER) else {
        return "Art-Net".to_string();
    };
    // The opcode is little-endian; reading it big-endian turns DMX (0x5000)
    // into 0x0050, which is not an opcode at all.
    let opcode = u16::from_le_bytes([head[8], head[9]]);
    let Some(name) = artnet_opcode(opcode) else {
        return format!("Art-Net (opcode {opcode:#06x})");
    };

    if opcode == 0x5000 {
        // Sequence, physical, universe, then the channel count.
        let body = &payload[ARTNET_HEADER + 2..];
        if let Some(fields) = body.get(..6) {
            let sequence = fields[0];
            let universe = u16::from_le_bytes([fields[2], fields[3]]);
            let channels = u16::from_be_bytes([fields[4], fields[5]]);
            return format!(
                "Art-Net DMX — universe {universe}, {channels} channels, seq {sequence}"
            );
        }
    }
    format!("Art-Net {name}")
}

fn describe_sacn(payload: &[u8]) -> String {
    if !looks_like_sacn(payload) {
        return "sACN (no identifier)".to_string();
    }
    let Some(&priority) = payload.get(SACN_PRIORITY) else {
        return "sACN".to_string();
    };
    let Some(&sequence) = payload.get(SACN_SEQUENCE) else {
        return "sACN".to_string();
    };
    let Some(universe) = payload
        .get(SACN_UNIVERSE..SACN_UNIVERSE + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
    else {
        return "sACN".to_string();
    };

    // The source name is how an operator identifies which console this is, and
    // is the only way to tell two senders apart when they conflict.
    let source = payload
        .get(SACN_SOURCE_NAME..SACN_SOURCE_NAME + 64)
        .and_then(|b| {
            let text: Vec<u8> = b.iter().copied().take_while(|&c| c != 0).collect();
            String::from_utf8(text).ok()
        })
        .filter(|s| !s.trim().is_empty());

    match source {
        Some(name) => format!(
            "sACN universe {universe} — priority {priority}, seq {sequence}, from '{}'",
            super::truncate(name.trim(), 40)
        ),
        None => format!("sACN universe {universe} — priority {priority}, seq {sequence}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Art-Net packet.
    fn artnet(opcode: u16, body: &[u8]) -> Vec<u8> {
        let mut p = ARTNET_ID.to_vec();
        p.extend_from_slice(&opcode.to_le_bytes());
        p.extend_from_slice(&[0x00, 0x0E]); // protocol version
        p.extend_from_slice(body);
        p
    }

    /// Build an sACN packet with the given universe, priority and source.
    fn sacn(universe: u16, priority: u8, sequence: u8, source: &str) -> Vec<u8> {
        let mut p = vec![0x00, 0x10, 0x00, 0x00];
        p.extend_from_slice(ACN_ID);
        p.resize(ACN_ROOT_LEN + 2 + 4, 0);
        let mut name = source.as_bytes().to_vec();
        name.resize(64, 0);
        p.extend_from_slice(&name);
        p.push(priority);
        p.extend_from_slice(&[0x00, 0x00]); // synchronisation address
        p.push(sequence);
        p.push(0x00); // options
        p.extend_from_slice(&universe.to_be_bytes());
        p
    }

    /// The reason this module exists: two consoles on one universe at the same
    /// priority, which each of them reports as working correctly.
    #[test]
    fn sacn_reports_the_universe_priority_and_source() {
        let r = dissect_sacn(None, None, 5568, 5568, &sacn(1, 100, 42, "Console A"));
        assert_eq!(r.protocol, Protocol::Sacn);
        assert_eq!(
            r.summary,
            "sACN universe 1 — priority 100, seq 42, from 'Console A'"
        );
    }

    /// Priority is what decides which of two sources the fixtures obey, so a
    /// conflict is only visible if both are read.
    #[test]
    fn two_sources_on_one_universe_are_distinguishable() {
        let a = describe_sacn(&sacn(3, 100, 1, "Console A"));
        let b = describe_sacn(&sacn(3, 100, 1, "Console B"));
        assert!(a.contains("universe 3") && a.contains("priority 100"));
        assert!(b.contains("Console B"), "{b}");
        assert_ne!(a, b);
    }

    /// Art-Net's opcode is little-endian. Read the other way round, DMX
    /// (0x5000) becomes 0x0050, which is not an opcode at all.
    #[test]
    fn the_artnet_opcode_is_little_endian() {
        let dmx = artnet(0x5000, &[7, 0, 1, 0, 0x02, 0x00]);
        let summary = describe_artnet(&dmx);
        assert!(summary.contains("Art-Net DMX"), "{summary}");
        assert!(!summary.contains("opcode"), "{summary}");
    }

    /// A DMX frame names the universe it drives and the channel count, and
    /// carries the sequence whose gaps are visible on stage.
    #[test]
    fn an_artnet_dmx_frame_reports_universe_and_sequence() {
        // Sequence 7, physical 0, universe 1 (little-endian), 512 channels.
        let dmx = artnet(0x5000, &[7, 0, 0x01, 0x00, 0x02, 0x00]);
        assert_eq!(
            describe_artnet(&dmx),
            "Art-Net DMX — universe 1, 512 channels, seq 7"
        );
    }

    #[test]
    fn the_other_artnet_opcodes_are_named() {
        assert_eq!(describe_artnet(&artnet(0x2000, &[])), "Art-Net Poll");
        assert_eq!(describe_artnet(&artnet(0x2100, &[])), "Art-Net PollReply");
        assert_eq!(describe_artnet(&artnet(0x5200, &[])), "Art-Net sync");
    }

    /// Both are recognised on their identifiers, which are fixed strings.
    #[test]
    fn recognition_rests_on_the_identifiers() {
        assert!(looks_like_artnet(&artnet(0x2000, &[])));
        assert!(!looks_like_artnet(b"Art-Netx"));
        assert!(!looks_like_artnet(&[]));

        assert!(looks_like_sacn(&sacn(1, 100, 1, "x")));
        // Right identifier, wrong preamble.
        let mut bad = sacn(1, 100, 1, "x");
        bad[1] = 0x11;
        assert!(!looks_like_sacn(&bad));
        assert!(!looks_like_sacn(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe_artnet(&[]), "Art-Net (no identifier)");
        assert_eq!(describe_artnet(ARTNET_ID), "Art-Net");
        // A DMX opcode whose body has not arrived falls back to the name.
        assert_eq!(describe_artnet(&artnet(0x5000, &[])), "Art-Net DMX");
        assert_eq!(describe_sacn(&[]), "sACN (no identifier)");
        assert_eq!(describe_sacn(&[0u8; 100]), "sACN (no identifier)");
        // A source name that is entirely padding is not reported as empty.
        assert_eq!(
            describe_sacn(&sacn(2, 50, 3, "")),
            "sACN universe 2 — priority 50, seq 3"
        );
    }
}
