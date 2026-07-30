// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for an HL7 v2 message wrapped in MLLP: an optional leading
/// VT byte (0x0B) followed by an "MSH" segment.
pub fn looks_like_hl7(p: &[u8]) -> bool {
    let body = if p.first() == Some(&0x0B) { &p[1..] } else { p };
    body.starts_with(b"MSH")
}

/// Dissect an HL7 v2 message (TCP 2575, MLLP-framed) — the format hospitals
/// use to exchange patient/admission/lab data. MSH-9 carries the message type
/// (e.g. ADT^A01 = patient admit).
pub fn dissect_hl7(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let body = if payload.first() == Some(&0x0B) {
        &payload[1..]
    } else {
        payload
    };
    // MSH-1 is the field separator (the char right after "MSH"); MSH-9 (index 8)
    // is the message type.
    let summary = if body.len() > 3 && body.starts_with(b"MSH") {
        let sep = body[3] as char;
        let text = String::from_utf8_lossy(&body[..body.len().min(256)]);
        let msg_type = text.split(sep).nth(8).unwrap_or("").trim();
        if msg_type.is_empty() {
            "HL7 v2 message (MLLP)".to_string()
        } else {
            format!("HL7 {} (MLLP)", super::truncate(msg_type, 24))
        }
    } else if let Some(fhir_res) = detect_fhir_resource(payload) {
        format!("HL7 FHIR REST — {fhir_res}")
    } else {
        "HL7 v2 message".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Hl7,
        summary,
    }
}

pub fn detect_fhir_resource(payload: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(payload);
    let lower = text.to_lowercase();
    if lower.contains("/fhir/") || lower.contains("\"resourcetype\"") {
        if lower.contains("patient") {
            Some("Patient Resource")
        } else if lower.contains("observation") {
            Some("Observation Resource")
        } else if lower.contains("encounter") {
            Some("Encounter Resource")
        } else if lower.contains("diagnosticreport") {
            Some("DiagnosticReport Resource")
        } else if lower.contains("medicationrequest") {
            Some("MedicationRequest Resource")
        } else {
            Some("FHIR Resource Payload")
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adt_admit() {
        let msg = b"\x0bMSH|^~\\&|SEND|FAC|RECV|FAC|20260101||ADT^A01|MSG1|P|2.5\r";
        assert!(looks_like_hl7(msg));
        let r = dissect_hl7(None, None, 40000, 2575, msg);
        assert_eq!(r.protocol, Protocol::Hl7);
        assert_eq!(r.summary, "HL7 ADT^A01 (MLLP)");
    }
}
