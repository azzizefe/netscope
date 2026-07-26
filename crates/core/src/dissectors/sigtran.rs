// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for SIGTRAN adaptation-layer dissectors (M2PA, M2UA, M3UA,
//! SUA). Each carries the same MTP3 User Adaptation header wrapping an upper-
//! layer payload, so this module extracts the common fields.

use std::ops::{Index, RangeFrom};

/// Parse a SIGTRAN common header and its parameters from a payload.
pub fn parse(payload: &[u8]) -> Option<SigtranHeader> {
    if payload.len() < 8 {
        return None;
    }
    let version = payload[0];
    let message_class = payload[2];
    let message_type = payload[3];
    let message_length = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if message_length < 8 || payload.len() < message_length {
        return None;
    }
    let mut parameters = Vec::new();
    let mut pos = 8;
    while pos + 4 <= message_length.min(payload.len()) {
        let tag = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        let total = 4 + len;
        if pos + total > message_length.min(payload.len()) {
            break;
        }
        let padded = (total + 3) & !3;
        parameters.push(Parameter {
            tag,
            value: payload[pos + 4..pos + total].to_vec(),
        });
        pos += padded;
    }
    Some(SigtranHeader {
        version,
        message_class,
        message_type,
        message_length,
        parameters,
    })
}

/// A parsed SIGTRAN common header with parameters.
pub struct SigtranHeader {
    pub version: u8,
    pub message_class: u8,
    pub message_type: u8,
    pub message_length: usize,
    pub parameters: Vec<Parameter>,
}

/// One SIGTRAN message parameter (tag-length-value).
pub struct Parameter {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl Parameter {
    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl Index<usize> for Parameter {
    type Output = u8;
    fn index(&self, idx: usize) -> &u8 {
        &self.value[idx]
    }
}

impl Index<RangeFrom<usize>> for Parameter {
    type Output = [u8];
    fn index(&self, range: RangeFrom<usize>) -> &[u8] {
        &self.value[range]
    }
}

/// SIGTRAN protocol data parameter tag.
pub const PARAM_PROTOCOL_DATA: u16 = 0x0210;

/// Human-readable name for a SIGTRAN message class.
pub fn class_name(class: u8) -> Option<&'static str> {
    Some(match class {
        0 => "Management",
        1 => "Transfer",
        2 => "SSNM",
        3 => "ASPSM",
        4 => "ASPTM",
        5 => "QPTM",
        6 => "M2UA",
        7 => "CL",
        8 => "CO",
        9 => "RKM",
        10 => "IIM",
        11 => "M2PA",
        _ => return None,
    })
}

/// Find a parameter by tag in a Vec.
pub fn find_parameter(params: Vec<Parameter>, tag: u16) -> Option<Parameter> {
    params.into_iter().find(|p| p.tag == tag)
}

/// Produce a summary for a SIGTRAN adaptation-layer PDU.
pub fn summarize(
    name: &str,
    payload: &[u8],
    message_name: fn(u8, u8) -> Option<&'static str>,
) -> String {
    if payload.len() < 8 {
        return format!("{name} — truncated header ({} bytes)", payload.len());
    }
    let version = payload[0];
    let msg_class = payload[2];
    let msg_type = payload[3];
    if version != 1 {
        return format!("{name} — unknown version {version}");
    }
    let label = message_name(msg_type, msg_class).unwrap_or("unknown message");
    let class_str = class_name(msg_class).unwrap_or("reserved");
    format!("{name} {label} ({class_str})")
}

#[cfg(test)]
pub mod test_helpers {
    /// Build a minimal SIGTRAN message for testing.
    pub fn sigtran(version: u8, msg_class: u8, msg_type: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(version);
        v.push(0x00); // reserved
        v.push(msg_class);
        let [_, lo] = msg_type.to_be_bytes();
        v.push(lo);
        let len = (8 + body.len()) as u32;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(body);
        v
    }
}
