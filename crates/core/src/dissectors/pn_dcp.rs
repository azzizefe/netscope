// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PROFINET DCP — how a device gets its name and address (IEC 61158-6-10 §4.3).
//!
//! PROFINET does not identify devices by IP address but by *name of station*.
//! An engineer commissioning a line assigns those names, and the controller
//! then looks up each one to find the device it is supposed to talk to. DCP is
//! the protocol that does both jobs: discovery (`Identify`) and assignment
//! (`Set`).
//!
//! This is worth reading because DCP `Set` is unauthenticated and takes effect
//! immediately. A single Set can rename a device or change its IP, and the
//! controller's very next cyclic exchange fails — the station it was
//! configured for no longer answers to that name. The device is up, the cable
//! is fine, and nothing in the IO traffic explains it. The Set that caused it
//! is often the only evidence, and it appears exactly once.
//!
//! It also carries the identity flood: an `Identify` request with the "all
//! selector" makes every device on the segment answer with its own name, which
//! is the fastest way to inventory a line — and, from an attacker's side, to
//! map it.

use crate::models::Protocol;

use super::DissectedResult;

/// Service identifiers. 0x00-0x02 are reserved or manufacturer specific.
const SERVICE_GET: u8 = 0x03;
const SERVICE_SET: u8 = 0x04;
const SERVICE_IDENTIFY: u8 = 0x05;
const SERVICE_HELLO: u8 = 0x06;

const TYPE_REQUEST: u8 = 0;
const TYPE_RESPONSE_OK: u8 = 1;
const TYPE_RESPONSE_UNSUPPORTED: u8 = 5;

/// Option 2, suboption 2 — the name a PROFINET controller resolves.
const OPTION_DEVICE: u8 = 0x02;
const SUBOPTION_NAME_OF_STATION: u8 = 0x02;
/// Option 1, suboption 2 — address, mask and gateway together.
const OPTION_IP: u8 = 0x01;
const SUBOPTION_IP_PARAMETER: u8 = 0x02;

/// Fixed part of the DCP header, before the first block.
const HEADER_LEN: usize = 10;

fn service_name(service: u8) -> Option<&'static str> {
    Some(match service {
        SERVICE_GET => "Get",
        SERVICE_SET => "Set",
        SERVICE_IDENTIFY => "Identify",
        SERVICE_HELLO => "Hello",
        _ => return None,
    })
}

/// Whether a PROFINET FrameID selects DCP.
pub(crate) fn is_dcp_frame(frame_id: u16) -> bool {
    (0xFEFC..=0xFEFF).contains(&frame_id)
}

/// One decoded block of interest.
enum Found {
    Station(String),
    Ip(String),
}

/// Walk the block list, returning the first block worth naming.
///
/// The blocks are walked rather than searched: a station name is free-form
/// text and can contain any byte pair, including one that looks exactly like
/// the option/suboption header of the block that would follow it.
fn walk_blocks(mut blocks: &[u8], service: u8, is_response: bool) -> Option<Found> {
    let mut found = None;
    while blocks.len() >= 4 {
        let option = blocks[0];
        let suboption = blocks[1];
        let length = u16::from_be_bytes([blocks[2], blocks[3]]) as usize;
        let body = blocks.get(4..4 + length)?;

        // A response to a query prefixes the value with BlockInfo, and a Set
        // request prefixes it with BlockQualifier. Both are two bytes and both
        // shift the value — reading at a fixed offset gets the wrong bytes.
        let prefixed = matches!(
            (service, is_response),
            (SERVICE_IDENTIFY, true) | (SERVICE_HELLO, false) | (SERVICE_GET, true)
        ) || (service == SERVICE_SET && !is_response);
        let value = if prefixed { body.get(2..)? } else { body };

        if found.is_none() {
            found = match (option, suboption) {
                (OPTION_DEVICE, SUBOPTION_NAME_OF_STATION) => std::str::from_utf8(value)
                    .ok()
                    .map(|s| Found::Station(super::truncate(s.trim_end_matches('\0'), 64))),
                (OPTION_IP, SUBOPTION_IP_PARAMETER) => value
                    .get(..4)
                    .map(|ip| Found::Ip(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))),
                _ => None,
            };
        }

        // Blocks are padded to an even length; the padding is not counted in
        // the block's own length field.
        let consumed = 4 + length + (length & 1);
        blocks = blocks.get(consumed..)?;
    }
    found
}

/// Dissect a PROFINET DCP frame, from behind the two-byte FrameID.
pub fn dissect_pn_dcp(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::PnDcp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "PROFINET DCP (truncated)".to_string();
    };
    let service = head[0];
    let service_type = head[1];
    let Some(name) = service_name(service) else {
        return format!("PROFINET DCP (service {service})");
    };

    let is_response = service_type != TYPE_REQUEST;
    let suffix = match service_type {
        TYPE_REQUEST => "",
        TYPE_RESPONSE_OK => " response",
        TYPE_RESPONSE_UNSUPPORTED => " — not supported by this device",
        _ => " response",
    };

    // DCPDataLength bounds the blocks; trusting the frame length instead would
    // read padding as a block.
    let data_length = u16::from_be_bytes([head[8], head[9]]) as usize;
    let blocks = payload
        .get(HEADER_LEN..HEADER_LEN + data_length)
        .unwrap_or(payload.get(HEADER_LEN..).unwrap_or(&[]));

    match walk_blocks(blocks, service, is_response) {
        // The rename that breaks a controller's next cycle.
        Some(Found::Station(station)) if service == SERVICE_SET && !is_response => {
            format!("PROFINET DCP Set — name of station := '{station}'")
        }
        Some(Found::Ip(ip)) if service == SERVICE_SET && !is_response => {
            format!("PROFINET DCP Set — IP := {ip}")
        }
        Some(Found::Station(station)) => {
            format!("PROFINET DCP {name}{suffix} — '{station}'")
        }
        Some(Found::Ip(ip)) => format!("PROFINET DCP {name}{suffix} — {ip}"),
        None => format!("PROFINET DCP {name}{suffix}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DCP frame carrying one block.
    fn frame(service: u8, service_type: u8, option: u8, suboption: u8, value: &[u8]) -> Vec<u8> {
        // Responses and Set requests carry two bytes ahead of the value.
        let is_response = service_type != TYPE_REQUEST;
        let prefixed = matches!(
            (service, is_response),
            (SERVICE_IDENTIFY, true) | (SERVICE_HELLO, false) | (SERVICE_GET, true)
        ) || (service == SERVICE_SET && !is_response);

        let mut body = Vec::new();
        if prefixed {
            body.extend_from_slice(&[0x00, 0x00]);
        }
        body.extend_from_slice(value);

        let mut block = vec![option, suboption];
        block.extend_from_slice(&(body.len() as u16).to_be_bytes());
        block.extend_from_slice(&body);
        if body.len() % 2 == 1 {
            block.push(0);
        }

        let mut p = vec![service, service_type];
        p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&(block.len() as u16).to_be_bytes());
        p.extend_from_slice(&block);
        p
    }

    /// The reason this dissector exists: an unauthenticated rename that takes
    /// effect at once and breaks the controller's next cycle.
    #[test]
    fn a_set_of_the_station_name_is_spelled_out() {
        let p = frame(
            SERVICE_SET,
            TYPE_REQUEST,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"turbine-3",
        );
        let r = dissect_pn_dcp(&p);
        assert_eq!(r.protocol, Protocol::PnDcp);
        assert_eq!(
            r.summary,
            "PROFINET DCP Set — name of station := 'turbine-3'"
        );
    }

    /// Changing a device's address does the same damage by a different route.
    #[test]
    fn a_set_of_the_ip_is_spelled_out() {
        let p = frame(
            SERVICE_SET,
            TYPE_REQUEST,
            OPTION_IP,
            SUBOPTION_IP_PARAMETER,
            &[192, 168, 0, 5, 255, 255, 255, 0, 0, 0, 0, 0],
        );
        assert_eq!(describe(&p), "PROFINET DCP Set — IP := 192.168.0.5");
    }

    /// An Identify response is how a line is inventoried — each device
    /// answering with its own name.
    #[test]
    fn an_identify_response_carries_the_station_name() {
        let p = frame(
            SERVICE_IDENTIFY,
            TYPE_RESPONSE_OK,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"turbine-3",
        );
        assert_eq!(describe(&p), "PROFINET DCP Identify response — 'turbine-3'");
    }

    /// A response and a request differ by exactly two bytes ahead of the
    /// value. Reading the value at one fixed offset gets the other one wrong.
    #[test]
    fn the_block_prefix_is_accounted_for_in_both_directions() {
        let request = frame(
            SERVICE_IDENTIFY,
            TYPE_REQUEST,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"press-1",
        );
        assert!(
            describe(&request).contains("'press-1'"),
            "{}",
            describe(&request)
        );

        let response = frame(
            SERVICE_GET,
            TYPE_RESPONSE_OK,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"press-1",
        );
        assert!(
            describe(&response).contains("'press-1'"),
            "{}",
            describe(&response)
        );
    }

    /// A device refusing the request is its own answer.
    #[test]
    fn an_unsupported_service_is_reported_as_such() {
        let p = frame(
            SERVICE_SET,
            TYPE_RESPONSE_UNSUPPORTED,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"x",
        );
        assert!(
            describe(&p).contains("not supported by this device"),
            "{}",
            describe(&p)
        );
    }

    /// Blocks are walked, not searched. A station name is free-form text and
    /// can contain the exact byte pair that opens the next block.
    #[test]
    fn a_name_that_looks_like_a_block_header_does_not_confuse_the_walk() {
        // The name embeds option 1 / suboption 2 — the IP parameter header.
        let p = frame(
            SERVICE_SET,
            TYPE_REQUEST,
            OPTION_DEVICE,
            SUBOPTION_NAME_OF_STATION,
            b"\x01\x02rig",
        );
        let summary = describe(&p);
        assert!(summary.contains("name of station"), "{summary}");
        assert!(!summary.contains("IP :="), "{summary}");
    }

    /// The FrameID range is what routes a PROFINET frame here.
    #[test]
    fn only_the_dcp_frame_ids_are_claimed() {
        for id in 0xFEFC..=0xFEFFu16 {
            assert!(is_dcp_frame(id), "{id:#06x}");
        }
        assert!(!is_dcp_frame(0xFEFB));
        assert!(!is_dcp_frame(0x8000));
        assert!(!is_dcp_frame(0xFC01));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "PROFINET DCP (truncated)");
        assert_eq!(describe(&[SERVICE_SET; 9]), "PROFINET DCP (truncated)");
        // Header present, no blocks.
        assert_eq!(
            describe(&[SERVICE_IDENTIFY, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "PROFINET DCP Identify"
        );
        // A block promising more than the frame holds.
        let mut short = vec![SERVICE_SET, 0, 0, 0, 0, 0, 0, 0, 0, 8];
        short.extend_from_slice(&[OPTION_DEVICE, SUBOPTION_NAME_OF_STATION, 0xFF, 0xFF]);
        assert_eq!(describe(&short), "PROFINET DCP Set");
        // A service the protocol does not define.
        assert_eq!(
            describe(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "PROFINET DCP (service 9)"
        );
    }
}
