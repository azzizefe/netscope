// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! OBD-II over CAN — what a diagnostic scanner asks a car, and what it hears.
//!
//! Unlike most CAN traffic, this is identifiable with certainty: the standard
//! fixes the identifiers. 0x7DF is a request to whichever ECU can answer,
//! 0x7E0–0x7E7 address one directly, and 0x7E8–0x7EF are the replies. Nothing
//! else may use them, so a frame on one of these identifiers is OBD-II.
//!
//! Because the encodings are fixed by the standard too, a reply can be turned
//! into the number a mechanic would read off a scan tool — engine speed in rpm,
//! coolant in degrees — rather than left as two bytes of hex.

use crate::models::Protocol;

use super::DissectedResult;

/// The request identifier every ECU listens on.
const ID_REQUEST_BROADCAST: u32 = 0x7DF;
/// Requests addressed to a single ECU.
const ID_REQUEST_FIRST: u32 = 0x7E0;
const ID_REQUEST_LAST: u32 = 0x7E7;
/// Replies. The offset from the request identifier is fixed at eight.
const ID_RESPONSE_FIRST: u32 = 0x7E8;
const ID_RESPONSE_LAST: u32 = 0x7EF;

/// A reply's service byte is the request's plus this.
const RESPONSE_OFFSET: u8 = 0x40;
/// A negative reply uses this service byte whatever was asked.
const NEGATIVE_RESPONSE: u8 = 0x7F;

/// Whether an 11-bit identifier belongs to OBD-II.
pub(crate) fn owns_id(id: u32) -> bool {
    id == ID_REQUEST_BROADCAST
        || (ID_REQUEST_FIRST..=ID_REQUEST_LAST).contains(&id)
        || (ID_RESPONSE_FIRST..=ID_RESPONSE_LAST).contains(&id)
}

fn is_response(id: u32) -> bool {
    (ID_RESPONSE_FIRST..=ID_RESPONSE_LAST).contains(&id)
}

/// Services (called modes on older scan tools).
fn service_name(service: u8) -> Option<&'static str> {
    Some(match service {
        0x01 => "current data",
        0x02 => "freeze-frame data",
        0x03 => "stored fault codes",
        0x04 => "clear fault codes",
        0x05 => "oxygen sensor results",
        0x06 => "on-board test results",
        0x07 => "pending fault codes",
        0x08 => "control operation",
        0x09 => "vehicle information",
        0x0A => "permanent fault codes",
        _ => return None,
    })
}

/// Why a request was refused.
fn refusal_reason(code: u8) -> &'static str {
    match code {
        0x10 => "general reject",
        0x11 => "service not supported",
        0x12 => "sub-function not supported",
        0x21 => "busy, repeat request",
        0x22 => "conditions not correct",
        0x31 => "request out of range",
        0x78 => "busy, response pending",
        _ => "refused",
    }
}

/// The parameters a scan tool actually polls, with the name and unit the
/// standard assigns.
fn parameter_name(pid: u8) -> Option<&'static str> {
    Some(match pid {
        0x00 | 0x20 | 0x40 => "supported parameters",
        0x01 => "monitor status",
        0x03 => "fuel system status",
        0x04 => "engine load",
        0x05 => "coolant temperature",
        0x0A => "fuel pressure",
        0x0B => "intake manifold pressure",
        0x0C => "engine speed",
        0x0D => "vehicle speed",
        0x0E => "timing advance",
        0x0F => "intake air temperature",
        0x10 => "mass air flow",
        0x11 => "throttle position",
        0x1F => "run time since start",
        0x21 => "distance with fault lamp lit",
        0x2F => "fuel level",
        0x31 => "distance since codes cleared",
        0x33 => "barometric pressure",
        0x42 => "control module voltage",
        0x46 => "ambient air temperature",
        0x5C => "engine oil temperature",
        _ => return None,
    })
}

/// Convert a reply's bytes into the value a scan tool would show.
///
/// Only the parameters whose formula the standard fixes are converted; anything
/// else keeps its raw bytes rather than being given a plausible-looking number.
fn parameter_value(pid: u8, data: &[u8]) -> Option<String> {
    let a = *data.first()? as f64;
    let b = data.get(1).copied().unwrap_or(0) as f64;
    Some(match pid {
        0x04 | 0x11 | 0x2F => format!("{:.0}%", a * 100.0 / 255.0),
        0x05 | 0x0F | 0x46 => format!("{}°C", a as i32 - 40),
        0x5C => format!("{}°C", a as i32 - 40),
        0x0A | 0x0B | 0x33 => format!("{a:.0} kPa"),
        // Engine speed is reported in quarter-revolutions.
        0x0C => format!("{:.0} rpm", (a * 256.0 + b) / 4.0),
        0x0D => format!("{a:.0} km/h"),
        0x0E => format!("{:.1}° advance", a / 2.0 - 64.0),
        0x10 => format!("{:.1} g/s", (a * 256.0 + b) / 100.0),
        0x1F => format!("{:.0} s", a * 256.0 + b),
        0x21 | 0x31 => format!("{:.0} km", a * 256.0 + b),
        0x42 => format!("{:.2} V", (a * 256.0 + b) / 1000.0),
        _ => return None,
    })
}

/// Describe an OBD-II frame. `payload` is the CAN data field.
pub(crate) fn describe(id: u32, payload: &[u8]) -> String {
    // The first byte frames the message; for the single-frame case its low
    // nibble is the length and the service follows.
    let Some(&service) = payload.get(1) else {
        return "OBD-II frame".to_string();
    };

    if is_response(id) {
        if service == NEGATIVE_RESPONSE {
            let asked = payload.get(2).copied().unwrap_or(0);
            let reason = refusal_reason(payload.get(3).copied().unwrap_or(0));
            let what = service_name(asked)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("service 0x{asked:02X}"));
            return format!("OBD-II {what} refused — {reason}");
        }
        // A reply's service byte is the request's plus 0x40.
        let requested = service.wrapping_sub(RESPONSE_OFFSET);
        let name = match service_name(requested) {
            Some(n) => n,
            None => return format!("OBD-II response, service 0x{service:02X}"),
        };

        // Fault-code services answer with a count rather than a parameter.
        if matches!(requested, 0x03 | 0x07 | 0x0A) {
            return format!("OBD-II {name} — response");
        }

        let Some(&pid) = payload.get(2) else {
            return format!("OBD-II {name} — response");
        };
        let param = match parameter_name(pid) {
            Some(p) => p.to_string(),
            None => format!("parameter 0x{pid:02X}"),
        };
        return match parameter_value(pid, payload.get(3..).unwrap_or(&[])) {
            Some(value) => format!("OBD-II {param} — {value}"),
            None => format!("OBD-II {param} — response"),
        };
    }

    let name = match service_name(service) {
        Some(n) => n.to_string(),
        None => format!("service 0x{service:02X}"),
    };
    let addressed = if id == ID_REQUEST_BROADCAST {
        String::new()
    } else {
        format!(" (to ECU {})", id - ID_REQUEST_FIRST)
    };
    match payload.get(2).and_then(|&pid| {
        parameter_name(pid)
            .map(|p| p.to_string())
            .or(Some(format!("parameter 0x{pid:02X}")))
    }) {
        Some(param) if service == 0x01 || service == 0x02 => {
            format!("OBD-II request {param}{addressed}")
        }
        _ => format!("OBD-II request {name}{addressed}"),
    }
}

/// Build the result for an OBD-II frame lifted out of a CAN capture.
pub(crate) fn result(id: u32, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Obd2,
        summary: describe(id, payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-frame message: length nibble, service, then the rest.
    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![bytes.len() as u8];
        v.extend_from_slice(bytes);
        v.resize(8, 0x55); // scan tools pad with a filler byte
        v
    }

    /// The identifiers are fixed by the standard, which is what makes this the
    /// one CAN protocol that can be identified with certainty.
    #[test]
    fn only_the_standard_identifiers_are_claimed() {
        assert!(owns_id(0x7DF));
        assert!(owns_id(0x7E0));
        assert!(owns_id(0x7E8));
        assert!(owns_id(0x7EF));
        assert!(!owns_id(0x7F0));
        assert!(!owns_id(0x7DE));
        assert!(!owns_id(0x123));
    }

    /// The point of the whole exercise: a reply becomes the number a mechanic
    /// would read off a scan tool.
    #[test]
    fn replies_are_converted_to_real_units() {
        // Engine speed is in quarter-revolutions: 0x0BB8 / 4 = 750 rpm idle.
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x0C, 0x0B, 0xB8])),
            "OBD-II engine speed — 750 rpm"
        );
        // Coolant is offset by forty degrees, so 0x5A is 50°C, not 90.
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x05, 0x5A])),
            "OBD-II coolant temperature — 50°C"
        );
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x0D, 0x64])),
            "OBD-II vehicle speed — 100 km/h"
        );
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x42, 0x37, 0x1A])),
            "OBD-II control module voltage — 14.11 V"
        );
    }

    /// A percentage is a fraction of 255, not of 100.
    #[test]
    fn percentages_use_the_standard_scale() {
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x11, 0xFF])),
            "OBD-II throttle position — 100%"
        );
        assert_eq!(
            describe(0x7E8, &frame(&[0x41, 0x2F, 0x80])),
            "OBD-II fuel level — 50%"
        );
    }

    /// A request names what is being asked for, and says whether it went to one
    /// ECU or to all of them.
    #[test]
    fn requests_name_the_parameter_and_the_target() {
        assert_eq!(
            describe(0x7DF, &frame(&[0x01, 0x0C])),
            "OBD-II request engine speed"
        );
        assert_eq!(
            describe(0x7E0, &frame(&[0x01, 0x05])),
            "OBD-II request coolant temperature (to ECU 0)"
        );
    }

    /// Reading fault codes is why a scanner is plugged in at all.
    #[test]
    fn fault_code_services_are_named() {
        assert_eq!(
            describe(0x7DF, &frame(&[0x03])),
            "OBD-II request stored fault codes"
        );
        assert_eq!(
            describe(0x7E8, &frame(&[0x43, 0x02])),
            "OBD-II stored fault codes — response"
        );
        assert_eq!(
            describe(0x7DF, &frame(&[0x04])),
            "OBD-II request clear fault codes"
        );
    }

    /// A refusal explains why a scan tool is showing nothing, which otherwise
    /// looks like the tool being broken.
    #[test]
    fn a_refusal_gives_its_reason() {
        assert_eq!(
            describe(0x7E8, &frame(&[0x7F, 0x01, 0x12])),
            "OBD-II current data refused — sub-function not supported"
        );
        assert_eq!(
            describe(0x7E8, &frame(&[0x7F, 0x03, 0x21])),
            "OBD-II stored fault codes refused — busy, repeat request"
        );
    }

    /// A parameter with no fixed formula keeps its identity but not an invented
    /// number.
    #[test]
    fn a_parameter_without_a_formula_is_not_given_a_value() {
        let summary = describe(0x7E8, &frame(&[0x41, 0x03, 0x02, 0x00]));
        assert_eq!(summary, "OBD-II fuel system status — response");
        let summary = describe(0x7E8, &frame(&[0x41, 0x99, 0x12]));
        assert_eq!(summary, "OBD-II parameter 0x99 — response");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(0x7E8, &[]), "OBD-II frame");
        assert_eq!(describe(0x7E8, &[0x02]), "OBD-II frame");
        assert!(describe(0x7E8, &[0x02, 0x41]).contains("OBD-II"));
    }
}
