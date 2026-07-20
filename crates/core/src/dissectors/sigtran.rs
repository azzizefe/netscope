// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The common header shared by the SIGTRAN adaptation layers — M3UA, M2UA,
//! M2PA and SUA (RFC 4666 §1.3.1, and the same layout in RFC 3331 / RFC 4165 /
//! RFC 3868).
//!
//! These protocols exist to carry classic SS7 telephony signalling over IP.
//! Each one adapts a different layer of the SS7 stack, but they all frame
//! messages identically:
//!
//! ```text
//! 0                   1                   2                   3
//! +-------+-------+---------------+---------------+
//! | Vers  | Rsvd  | Message Class | Message Type  |
//! +-------+-------+---------------+---------------+
//! |              Message Length (4 bytes)         |
//! +-----------------------------------------------+
//! |              Parameters (TLV)...              |
//! ```
//!
//! Parameters that follow are tag/length/value, each padded to a 4-byte
//! boundary — that is how M3UA carries the SCCP message that carries the actual
//! telephony application.

/// The 8-byte common header every SIGTRAN adaptation layer starts with.
pub(crate) const COMMON_HEADER: usize = 8;

/// A decoded SIGTRAN common header.
pub(crate) struct Header<'a> {
    pub message_class: u8,
    pub message_type: u8,
    /// The parameter area after the header, trimmed to the declared length.
    pub parameters: &'a [u8],
}

/// Parse the common header. Returns `None` when the payload is too short or the
/// declared length is not consistent with the bytes present.
pub(crate) fn parse(payload: &[u8]) -> Option<Header<'_>> {
    if payload.len() < COMMON_HEADER {
        return None;
    }
    // Version 1 is the only version these RFCs define; anything else means we
    // are not looking at SIGTRAN and should not pretend to decode it.
    if payload[0] != 1 {
        return None;
    }
    let length = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if length < COMMON_HEADER {
        return None;
    }
    // A message may be truncated by the capture snap length, so take what is
    // there rather than rejecting it outright.
    let end = length.min(payload.len());
    Some(Header {
        message_class: payload[2],
        message_type: payload[3],
        parameters: &payload[COMMON_HEADER..end],
    })
}

/// Message classes, shared across the adaptation layers (RFC 4666 §3.1.2).
/// The class says what kind of business the message is doing; the type within
/// the class says which specific message.
pub(crate) fn class_name(class: u8) -> Option<&'static str> {
    Some(match class {
        0 => "MGMT",
        1 => "Transfer",
        2 => "SSNM",
        3 => "ASPSM",
        4 => "ASPTM",
        5 => "QPTM",
        6 => "MAUP",
        7 => "SUA-CL",
        8 => "SUA-CO",
        9 => "RKM",
        10 => "IIM",
        _ => return None,
    })
}

/// Walk the TLV parameter list, returning the value of the first parameter with
/// the given tag.
///
/// Each parameter is a 2-byte tag, a 2-byte length that *includes* those four
/// header bytes, then the value, padded out to a 4-byte boundary.
pub(crate) fn find_parameter(parameters: &[u8], want_tag: u16) -> Option<&[u8]> {
    let mut offset = 0usize;
    while offset + 4 <= parameters.len() {
        let tag = u16::from_be_bytes([parameters[offset], parameters[offset + 1]]);
        let len = u16::from_be_bytes([parameters[offset + 2], parameters[offset + 3]]) as usize;
        // A length below the 4-byte header, or past the buffer, is malformed —
        // stop rather than looping forever or reading out of bounds.
        if len < 4 || offset + len > parameters.len() {
            return None;
        }
        if tag == want_tag {
            return Some(&parameters[offset + 4..offset + len]);
        }
        offset += len.div_ceil(4) * 4;
    }
    None
}

/// Render the standard summary line for an adaptation layer that has nothing
/// to add beyond its message name.
///
/// `message_name` maps a (class, type) pair to its name. When the type is
/// unknown but the class is not, the class still narrows down what the message
/// is doing, so report that rather than giving up.
pub(crate) fn summarize(
    name: &str,
    payload: &[u8],
    message_name: fn(u8, u8) -> Option<&'static str>,
) -> String {
    let Some(h) = parse(payload) else {
        return format!("{name} ({})", super::bytes(payload.len() as u64));
    };
    match message_name(h.message_class, h.message_type) {
        Some(msg) => format!("{name} {msg}"),
        None => match class_name(h.message_class) {
            Some(class) => format!("{name} {class} message {}", h.message_type),
            None => format!(
                "{name} class {} message {}",
                h.message_class, h.message_type
            ),
        },
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::COMMON_HEADER;

    /// Build a SIGTRAN message with one TLV parameter.
    pub fn sigtran(class: u8, msg_type: u8, tag: u16, value: &[u8]) -> Vec<u8> {
        let mut params = Vec::new();
        params.extend_from_slice(&tag.to_be_bytes());
        params.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
        params.extend_from_slice(value);
        while params.len() % 4 != 0 {
            params.push(0);
        }
        let mut p = vec![1u8, 0, class, msg_type];
        p.extend_from_slice(&((COMMON_HEADER + params.len()) as u32).to_be_bytes());
        p.extend_from_slice(&params);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::sigtran;
    use super::*;

    #[test]
    fn parses_class_and_type() {
        let p = sigtran(1, 1, 0x0210, b"data");
        let h = parse(&p).expect("valid header");
        assert_eq!(h.message_class, 1);
        assert_eq!(h.message_type, 1);
        assert_eq!(class_name(h.message_class), Some("Transfer"));
    }

    #[test]
    fn finds_a_parameter_by_tag() {
        let p = sigtran(1, 1, 0x0210, b"payload!");
        let h = parse(&p).unwrap();
        assert_eq!(find_parameter(h.parameters, 0x0210), Some(&b"payload!"[..]));
        assert_eq!(find_parameter(h.parameters, 0x0006), None);
    }

    /// Only version 1 exists; rejecting anything else keeps us from decoding
    /// unrelated traffic that happens to land on the same association.
    #[test]
    fn rejects_a_foreign_version() {
        let mut p = sigtran(1, 1, 0x0210, b"x");
        p[0] = 9;
        assert!(parse(&p).is_none());
    }

    #[test]
    fn truncated_message_yields_what_is_present() {
        let mut p = sigtran(1, 1, 0x0210, b"abcdefgh");
        p.truncate(12); // snap length cut the parameters short
        let h = parse(&p).expect("header is still complete");
        assert_eq!(h.parameters.len(), 4);
    }

    #[test]
    fn malformed_parameter_length_terminates_the_walk() {
        // A parameter claiming to be 2 bytes long cannot hold its own header.
        let params = [0x02, 0x10, 0x00, 0x02, 0xff, 0xff];
        assert!(find_parameter(&params, 0x0210).is_none());
        // And one claiming more than the buffer holds.
        let params = [0x02, 0x10, 0xff, 0xff, 0xff, 0xff];
        assert!(find_parameter(&params, 0x0210).is_none());
    }

    #[test]
    fn short_payload_is_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[1, 0, 1, 1]).is_none());
    }
}
