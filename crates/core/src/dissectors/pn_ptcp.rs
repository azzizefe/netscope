// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PROFINET PTCP — the clock every isochronous cycle depends on.
//!
//! PROFINET's fastest mode, IRT, does not send data whenever it is ready; it
//! sends on a schedule that every device on the segment shares. That schedule
//! only works if the devices agree what time it is to within a fraction of a
//! microsecond, and PTCP is how they agree.
//!
//! A sync master sends Announce frames carrying the time. Each device measures
//! the cable delay to its neighbours with the Delay frames, so it can correct
//! for propagation, and FollowUp frames carry the precise send timestamp that
//! could not be written into the Announce before it left.
//!
//! The reason to read it is that when synchronisation degrades, the symptom is
//! not a clock problem. It is IO data arriving in the wrong cycle, which
//! presents as intermittent process faults on devices that are individually
//! healthy — and the sync master's Announce frames stopping, or the measured
//! delays jumping, is the only place the real cause is visible. A device that
//! has lost sync will drop out of the IRT schedule entirely.
//!
//! FrameIDs 0xFF00-0xFF43 are all PTCP. Note that this range was previously
//! reported as "RT Class 3 (isochronous)", which is wrong: RT Class 3 uses the
//! low FrameIDs, and this range is the clock protocol underneath it.

use crate::models::Protocol;

use super::DissectedResult;

/// What the frame is doing, from its FrameID.
///
/// The three groups are separate ranges rather than one, with reserved gaps
/// between them, so a range test is what identifies them — not a bit pattern.
fn frame_purpose(frame_id: u16) -> Option<&'static str> {
    Some(match frame_id {
        0xFF00..=0xFF01 => "Announce",
        0xFF02..=0xFF1F => "reserved",
        0xFF20..=0xFF21 => "FollowUp",
        0xFF22..=0xFF3F => "reserved",
        0xFF40..=0xFF43 => "Delay",
        _ => return None,
    })
}

/// Whether a PROFINET FrameID selects PTCP.
pub(crate) fn is_ptcp_frame(frame_id: u16) -> bool {
    (0xFF00..=0xFF43).contains(&frame_id)
}

/// What one TLV block in the frame carries.
fn block_name(block_type: u8) -> Option<&'static str> {
    Some(match block_type {
        0x00 => "End",
        0x01 => "Subdomain",
        0x02 => "Time",
        0x03 => "TimeExtension",
        0x04 => "Master",
        0x05 => "PortParameter",
        0x06 => "DelayParameter",
        0x07 => "PortTime",
        0x7F => "organisation-specific",
        _ => return None,
    })
}

/// Dissect a PROFINET PTCP frame, from behind the two-byte FrameID.
pub fn dissect_pn_ptcp(frame_id: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::PnPtcp,
        summary: describe(frame_id, payload),
    }
}

fn describe(frame_id: u16, payload: &[u8]) -> String {
    let Some(purpose) = frame_purpose(frame_id) else {
        return format!("PROFINET PTCP (FrameID {frame_id:#06x})");
    };

    // The header before the blocks is a fixed six bytes: sequence, reserved,
    // delay values. The blocks follow it, so walking from zero would read the
    // sequence number as a block type.
    let blocks = payload.get(6..).unwrap_or(&[]);
    let named = walk_blocks(blocks);

    match named {
        Some(block) => format!("PROFINET PTCP {purpose} — {block}"),
        None => format!("PROFINET PTCP {purpose}"),
    }
}

/// Walk the TLV blocks and name the first one that is not padding.
///
/// Walked rather than searched: a timestamp inside a Time block contains
/// arbitrary bytes, and any of them can look like the type/length pair that
/// opens the next block.
fn walk_blocks(mut blocks: &[u8]) -> Option<&'static str> {
    while blocks.len() >= 4 {
        let block_type = blocks[0];
        if block_type == 0x00 {
            return None;
        }
        let length = u16::from_be_bytes([blocks[2], blocks[3]]) as usize;
        if let Some(name) = block_name(block_type) {
            return Some(name);
        }
        blocks = blocks.get(4 + length..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PTCP payload: six-byte header, then one block.
    fn frame(block_type: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        p.push(block_type);
        p.push(0x00);
        p.extend_from_slice(&(body.len() as u16).to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    /// The reason this dissector exists: the clock protocol under IRT, whose
    /// failure presents as process faults rather than as a clock problem.
    #[test]
    fn the_three_frame_purposes_are_distinguished() {
        let r = dissect_pn_ptcp(0xFF00, &frame(0x02, &[0u8; 8]));
        assert_eq!(r.protocol, Protocol::PnPtcp);
        assert!(
            r.summary.starts_with("PROFINET PTCP Announce"),
            "{}",
            r.summary
        );

        assert!(describe(0xFF20, &frame(0x03, &[0u8; 4])).contains("FollowUp"));
        assert!(describe(0xFF40, &frame(0x06, &[0u8; 8])).contains("Delay"));
    }

    /// The whole 0xFF00-0xFF43 range is PTCP — this is the range that used to
    /// be reported as RT Class 3.
    #[test]
    fn the_whole_range_is_claimed() {
        for id in [0xFF00u16, 0xFF01, 0xFF20, 0xFF21, 0xFF40, 0xFF43] {
            assert!(is_ptcp_frame(id), "{id:#06x}");
            assert!(frame_purpose(id).is_some(), "{id:#06x}");
        }
        // Reserved gaps are inside the range and still PTCP.
        assert!(is_ptcp_frame(0xFF10));
        assert_eq!(frame_purpose(0xFF10), Some("reserved"));
        // Outside it is not.
        assert!(!is_ptcp_frame(0xFEFF));
        assert!(!is_ptcp_frame(0xFF44));
        assert!(!is_ptcp_frame(0x8000));
    }

    /// The block says what the frame actually carries — which master is
    /// claiming the clock, or what delay was measured.
    #[test]
    fn the_blocks_are_named() {
        assert!(describe(0xFF00, &frame(0x04, &[0u8; 8])).contains("Master"));
        assert!(describe(0xFF00, &frame(0x01, &[0u8; 8])).contains("Subdomain"));
        assert!(describe(0xFF40, &frame(0x06, &[0u8; 8])).contains("DelayParameter"));
    }

    /// The blocks start after a six-byte header. Walking from zero would read
    /// the sequence number as a block type.
    #[test]
    fn the_header_is_skipped_before_the_blocks() {
        // A header whose first byte is 0x04 — the Master block type. If the
        // header were not skipped this would be reported as a Master block.
        let mut p = vec![0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0]);
        assert!(
            describe(0xFF00, &p).contains("Subdomain"),
            "{}",
            describe(0xFF00, &p)
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(0xFF00, &[]), "PROFINET PTCP Announce");
        assert_eq!(describe(0xFF00, &[0u8; 6]), "PROFINET PTCP Announce");
        // A block promising more than the frame holds.
        let mut short = vec![0u8; 6];
        short.extend_from_slice(&[0x7E, 0x00, 0xFF, 0xFF]);
        assert_eq!(describe(0xFF00, &short), "PROFINET PTCP Announce");
        assert_eq!(describe(0x1234, &[]), "PROFINET PTCP (FrameID 0x1234)");
    }
}
