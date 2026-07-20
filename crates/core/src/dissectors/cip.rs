// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CIP — the object protocol inside EtherNet/IP.
//!
//! EtherNet/IP is only the envelope. What actually reads a tag from a
//! Rockwell/Allen-Bradley PLC, or downloads new logic to it, is a CIP request
//! carried inside a SendRRData or SendUnitData encapsulation message. Naming
//! the CIP service is what turns "EtherNet/IP SendRRData" into "CIP Read Tag"
//! or, more to the point, "CIP Stop" — the difference between a controller
//! being polled and a controller being halted.

use crate::models::Protocol;

/// The response bit, set in the service byte of a reply (CIP Vol 1 §2-4.2).
const SERVICE_RESPONSE: u8 = 0x80;

/// The service that tunnels a PCCC message rather than acting on a CIP object.
const SERVICE_EXECUTE_PCCC: u8 = 0x4B;

/// CIP service codes (CIP Volume 1, Appendix A) plus the Rockwell-specific
/// services that carry tag access on Logix controllers.
fn service_name(service: u8) -> Option<&'static str> {
    Some(match service {
        0x01 => "Get Attributes All",
        0x02 => "Set Attributes All",
        0x03 => "Get Attribute List",
        0x04 => "Set Attribute List",
        0x05 => "Reset",
        0x06 => "Start",
        0x07 => "Stop",
        0x08 => "Create",
        0x09 => "Delete",
        0x0A => "Multiple Service Packet",
        0x0D => "Apply Attributes",
        0x0E => "Get Attribute Single",
        0x10 => "Set Attribute Single",
        0x11 => "Find Next Object Instance",
        0x14 => "Error Response",
        0x15 => "Restore",
        0x16 => "Save",
        0x17 => "No Operation",
        0x18 => "Get Member",
        0x19 => "Set Member",
        0x1A => "Insert Member",
        0x1B => "Remove Member",
        0x1C => "Group Sync",
        0x4B => "Execute PCCC",
        0x4C => "Read Tag",
        0x4D => "Write Tag",
        0x4E => "Read Modify Write Tag",
        0x52 => "Read Tag Fragmented",
        0x53 => "Write Tag Fragmented",
        0x54 => "Forward Open",
        0x5A => "Unknown/Vendor",
        0x5B => "Get Instance Attribute List",
        _ => return None,
    })
}

/// CIP object classes (CIP Volume 1, Chapter 5). The class says which part of
/// the device is being addressed.
fn class_name(class: u16) -> Option<&'static str> {
    Some(match class {
        0x01 => "Identity",
        0x02 => "Message Router",
        0x04 => "Assembly",
        0x06 => "Connection Manager",
        0x07 => "Register",
        0x08 => "Discrete Input Point",
        0x09 => "Discrete Output Point",
        0x0A => "Analog Input Point",
        0x0B => "Analog Output Point",
        0x0E => "Presence Sensing",
        0x0F => "Parameter",
        0x28 => "Motor Data",
        0x29 => "Control Supervisor",
        0x2A => "AC/DC Drive",
        0x37 => "File",
        0x47 => "Device Level Ring",
        0x48 => "QoS",
        0x64 => "Symbol",
        0x6B => "Template",
        0xAC => "Logix Controller",
        0xF4 => "Port",
        0xF5 => "TCP/IP Interface",
        0xF6 => "Ethernet Link",
        _ => return None,
    })
}

/// CIP general status codes worth naming (CIP Volume 1, Appendix B).
fn status_name(status: u8) -> Option<&'static str> {
    Some(match status {
        0x00 => "success",
        0x01 => "connection failure",
        0x04 => "path segment error",
        0x05 => "path destination unknown",
        0x08 => "service not supported",
        0x09 => "invalid attribute value",
        0x0C => "object state conflict",
        0x0E => "attribute not settable",
        0x0F => "privilege violation",
        0x10 => "device state conflict",
        0x13 => "not enough data",
        0x14 => "attribute not supported",
        0x15 => "too much data",
        0x16 => "object does not exist",
        0x1E => "embedded service error",
        0x26 => "invalid path size",
        _ => return None,
    })
}

/// Read the class from a CIP request path.
///
/// The path is a series of segments. A logical class segment is `0x20` for an
/// 8-bit class id or `0x21` for a 16-bit one — the distinction matters because
/// reading a 16-bit class as 8-bit yields a plausible wrong object.
fn path_class(path: &[u8]) -> Option<u16> {
    match path.first()? {
        0x20 => path.get(1).map(|&c| c as u16),
        0x21 => {
            // 16-bit form: a pad byte follows the segment type.
            let lo = *path.get(2)? as u16;
            let hi = *path.get(3)? as u16;
            Some((hi << 8) | lo)
        }
        _ => None,
    }
}

/// Describe a CIP message, or `None` if it does not look like one.
///
/// Returns the protocol to label the packet with alongside the summary: an
/// Execute PCCC request is really a PCCC message, and reporting it as CIP would
/// leave the `Pccc` variant unreachable and make the protocol column disagree
/// with the summary next to it.
pub(crate) fn describe(payload: &[u8]) -> Option<(Protocol, String)> {
    let raw_service = *payload.first()?;
    let is_response = raw_service & SERVICE_RESPONSE != 0;
    let service = raw_service & !SERVICE_RESPONSE;
    let name = service_name(service)?;

    if is_response {
        // A response is: service, a reserved byte, then the general status.
        let status = *payload.get(2)?;
        let summary = match status_name(status) {
            Some("success") => format!("CIP {name} response"),
            Some(text) => format!("CIP {name} response — {text}"),
            None => format!("CIP {name} response — status 0x{status:02x}"),
        };
        return Some((Protocol::Cip, summary));
    }

    // A request is: service, the path size in 16-bit words, then the path.
    let path_words = *payload.get(1)? as usize;
    let path = payload.get(2..2 + path_words * 2)?;

    // Execute PCCC exists purely to tunnel the older Allen-Bradley command
    // set. The PCCC function is the useful part, so report that instead.
    if service == SERVICE_EXECUTE_PCCC {
        if let Some(body) = payload.get(2 + path_words * 2..) {
            if let Some(inner) = super::pccc::describe(body) {
                return Some((Protocol::Pccc, inner));
            }
        }
    }

    let summary = match path_class(path).and_then(class_name) {
        Some(class) => format!("CIP {name} — {class}"),
        None => format!("CIP {name}"),
    };
    Some((Protocol::Cip, summary))
}

// This module has no `dissect_*` entry point of its own.
//
// Its parent builds the result, because the parent is what knows the context
// the summary needs — the session handle, the point codes, the subsystem
// numbers. A second entry point here would be a code path nothing calls, free
// to drift out of step with the one that runs.

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Build a CIP request: service, path size in words, then an 8-bit logical
    /// class segment and an instance segment.
    pub fn request(service: u8, class: u8) -> Vec<u8> {
        vec![service, 0x02, 0x20, class, 0x24, 0x01]
    }

    /// Build a CIP response with the given general status.
    pub fn response(service: u8, status: u8) -> Vec<u8> {
        vec![service | 0x80, 0x00, status, 0x00]
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{request, response};
    use super::*;

    /// The summary alone, for the cases where the protocol label is not what is
    /// under test.
    fn describe_summary(payload: &[u8]) -> Option<String> {
        describe(payload).map(|(_, s)| s)
    }

    #[test]
    fn read_tag_is_named() {
        let p = request(0x4C, 0x6B);
        assert_eq!(
            describe(&p).as_ref().map(|(_, s)| s.as_str()),
            Some("CIP Read Tag — Template")
        );
    }

    /// The services that change what a controller is doing.
    #[test]
    fn stop_and_reset_are_named() {
        assert_eq!(
            describe_summary(&request(0x07, 0xAC)).as_deref(),
            Some("CIP Stop — Logix Controller")
        );
        assert_eq!(
            describe_summary(&request(0x05, 0x01)).as_deref(),
            Some("CIP Reset — Identity")
        );
    }

    #[test]
    fn write_tag_names_its_object() {
        assert_eq!(
            describe_summary(&request(0x4D, 0x64)).as_deref(),
            Some("CIP Write Tag — Symbol")
        );
    }

    /// The response bit shares the service byte; leaving it in would fail to
    /// match any service name at all.
    #[test]
    fn response_bit_is_masked_and_status_named() {
        assert_eq!(
            describe_summary(&response(0x4C, 0x00)).as_deref(),
            Some("CIP Read Tag response")
        );
        assert_eq!(
            describe_summary(&response(0x4C, 0x05)).as_deref(),
            Some("CIP Read Tag response — path destination unknown")
        );
        assert_eq!(
            describe_summary(&response(0x4D, 0x0F)).as_deref(),
            Some("CIP Write Tag response — privilege violation")
        );
    }

    /// A 16-bit class segment has a different layout; reading it as 8-bit would
    /// name the wrong object.
    #[test]
    fn sixteen_bit_class_segments_are_read_correctly() {
        // 0x21 = 16-bit logical class, pad, then class 0x00AC little-endian.
        let p = vec![0x4C, 0x03, 0x21, 0x00, 0xAC, 0x00, 0x24, 0x01];
        assert_eq!(
            describe(&p).as_ref().map(|(_, s)| s.as_str()),
            Some("CIP Read Tag — Logix Controller")
        );
    }

    /// Execute PCCC is a tunnel, so the PCCC function inside is the truer
    /// label than "CIP Execute PCCC" would be.
    #[test]
    fn execute_pccc_reports_the_tunnelled_function() {
        let inner = crate::dissectors::pccc::test_helpers::pccc(0x0F, 0xAA, 0x00);
        let mut p = vec![0x4B, 0x02, 0x20, 0x67, 0x24, 0x01];
        p.extend_from_slice(&inner);
        assert_eq!(
            describe(&p).as_ref().map(|(_, s)| s.as_str()),
            Some("PCCC Protected Typed Logical Write (3 address fields)")
        );
    }

    /// A tunnel carrying something that is not PCCC keeps the CIP label rather
    /// than being mislabelled.
    #[test]
    fn execute_pccc_with_unrecognised_body_stays_cip() {
        let p = vec![0x4B, 0x02, 0x20, 0x67, 0x24, 0x01, 0x00, 0xFF];
        assert_eq!(
            describe(&p).as_ref().map(|(_, s)| s.as_str()),
            Some("CIP Execute PCCC")
        );
    }

    #[test]
    fn unknown_class_still_names_the_service() {
        let p = request(0x4C, 0x7E);
        assert_eq!(
            describe(&p).as_ref().map(|(_, s)| s.as_str()),
            Some("CIP Read Tag")
        );
    }

    /// `describe` returning None is what tells EtherNet/IP the payload is not
    /// CIP, so an unknown service must not be claimed.
    #[test]
    fn unknown_service_is_not_claimed() {
        assert!(describe(&[0x7E, 0x02, 0x20, 0x01]).is_none());
        assert!(describe(&[]).is_none());
    }

    #[test]
    fn path_running_past_the_buffer_is_rejected() {
        // Claims a 10-word path with only four bytes present.
        assert!(describe(&[0x4C, 0x0A, 0x20, 0x01]).is_none());
    }

    /// Unrecognised bytes must yield nothing rather than a guess, since that
    /// is how EtherNet/IP learns to keep its own label.
    #[test]
    fn unrecognised_bytes_are_not_described() {
        assert!(describe(&request(0x4C, 0x6B)).is_some());
        assert!(describe(&[0xFF]).is_none());
    }
}
