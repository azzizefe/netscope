// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SCCP message types (ITU-T Q.713 §2.1). Mobile signalling is overwhelmingly
/// connectionless — UDT and its extended forms — because a location update or
/// an SMS routing query is one question and one answer.
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "CR",
        0x02 => "CC",
        0x03 => "CREF",
        0x04 => "RLSD",
        0x05 => "RLC",
        0x06 => "DT1",
        0x07 => "DT2",
        0x08 => "AK",
        0x09 => "UDT",
        0x0A => "UDTS",
        0x0B => "ED",
        0x0C => "EA",
        0x0D => "RSR",
        0x0E => "RSC",
        0x0F => "ERR",
        0x10 => "IT",
        0x11 => "XUDT",
        0x12 => "XUDTS",
        0x13 => "LUDT",
        0x14 => "LUDTS",
        _ => return None,
    })
}

/// Subsystem numbers (ITU-T Q.713 §3.4.2.2 and 3GPP TS 23.003). The subsystem
/// number is the most useful field in an SCCP header: it names *which network
/// element* is being addressed, so "SCCP UDT → HLR" says a subscriber database
/// is being queried, which is far more meaningful than a point code.
pub(crate) fn subsystem_name(ssn: u8) -> Option<&'static str> {
    Some(match ssn {
        1 => "SCCP mgmt",
        6 => "HLR",
        7 => "VLR",
        8 => "MSC",
        9 => "EIR",
        10 => "AUC",
        11 => "ISDN SS",
        12 => "reserved",
        13 => "BISDN",
        14 => "call control",
        142 => "RANAP",
        143 => "RNSAP",
        145 => "GMLC",
        146 => "CAP",
        147 => "gsmSCF",
        148 => "SIWF",
        149 => "SGSN",
        150 => "GGSN",
        251 => "BSC (BSSAP-LE)",
        252 => "MSC (BSSAP-LE)",
        253 => "SMLC (BSSAP-LE)",
        254 => "BSS O&M",
        255 => "BSSAP",
        _ => return None,
    })
}

/// A parsed connectionless SCCP message.
pub(crate) struct Udt<'a> {
    pub called_ssn: Option<u8>,
    pub calling_ssn: Option<u8>,
    /// The user data, which for mobile signalling is a TCAP message.
    pub data: &'a [u8],
}

/// Read one variable parameter given the offset of its pointer.
///
/// SCCP pointers are relative to the pointer's own position, not to the start
/// of the message — a detail worth stating because getting it wrong yields
/// plausible-looking garbage rather than an obvious failure.
fn parameter_at(payload: &[u8], pointer_offset: usize) -> Option<&[u8]> {
    let pointer = *payload.get(pointer_offset)? as usize;
    if pointer == 0 {
        return None; // a null pointer means the parameter is absent
    }
    let start = pointer_offset.checked_add(pointer)?;
    let len = *payload.get(start)? as usize;
    let from = start.checked_add(1)?;
    let to = from.checked_add(len)?;
    payload.get(from..to)
}

/// Pull the subsystem number out of an SCCP address parameter (Q.713 §3.4.2.1).
///
/// The address begins with an indicator byte saying which of the optional
/// fields follow. The point code, when present, comes first and is two bytes;
/// the subsystem number follows it.
fn address_ssn(address: &[u8]) -> Option<u8> {
    let indicator = *address.first()?;
    let has_point_code = indicator & 0x01 != 0;
    let has_ssn = indicator & 0x02 != 0;
    if !has_ssn {
        return None;
    }
    let ssn_offset = 1 + if has_point_code { 2 } else { 0 };
    address.get(ssn_offset).copied()
}

/// Parse a connectionless SCCP message (UDT / XUDT and their service variants).
///
/// UDT carries three pointers — to the called address, the calling address and
/// the data. XUDT inserts a hop counter first, shifting everything by one.
pub(crate) fn parse_udt(payload: &[u8]) -> Option<Udt<'_>> {
    let msg_type = *payload.first()?;
    // Offset of the first pointer: after type + protocol class, plus the hop
    // counter that the extended forms add.
    let first_pointer = match msg_type {
        0x09 | 0x0A => 2,
        0x11..=0x14 => 3,
        _ => return None,
    };
    let called = parameter_at(payload, first_pointer);
    let calling = parameter_at(payload, first_pointer + 1);
    let data = parameter_at(payload, first_pointer + 2)?;
    Some(Udt {
        called_ssn: called.and_then(address_ssn),
        calling_ssn: calling.and_then(address_ssn),
        data,
    })
}

/// Render a subsystem number for display, naming it when we know it.
fn ssn_label(ssn: Option<u8>) -> String {
    match ssn {
        Some(n) => match subsystem_name(n) {
            Some(name) => name.to_string(),
            None => format!("SSN {n}"),
        },
        None => "?".to_string(),
    }
}

/// Hand the user data to the protocol its called subsystem names.
///
/// Returns `None` for subsystems with no dedicated dissector, so the caller can
/// fall back to TCAP and then to a plain SCCP summary.
fn dissect_subsystem(
    called_ssn: Option<u8>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) -> Option<DissectedResult> {
    if data.is_empty() {
        return None;
    }
    match called_ssn? {
        142 => Some(super::ranap::dissect_ranap(
            src_ip, dst_ip, src_port, dst_port, data,
        )),
        143 => Some(super::rnsap::dissect_rnsap(
            src_ip, dst_ip, src_port, dst_port, data,
        )),
        254 | 255 => Some(super::bssap::dissect_bssap(
            src_ip, dst_ip, src_port, dst_port, data,
        )),
        _ => None,
    }
}

/// Dissect an SCCP message. SCCP rides inside M3UA (service indicator 3) rather
/// than on a port of its own, so it is reached from the M3UA dissector.
///
/// When the message is connectionless and carries user data, that data is a
/// TCAP message and is handed on — the operation inside is what actually says
/// what the network is doing.
pub fn dissect_sccp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sccp,
        summary,
    };

    let Some(&msg_type) = payload.first() else {
        return fallback("SCCP (empty)".into());
    };
    let name = match message_name(msg_type) {
        Some(n) => n,
        None => return fallback(format!("SCCP message 0x{msg_type:02x}")),
    };

    match parse_udt(payload) {
        Some(udt) => {
            let route = format!(
                "{} → {}",
                ssn_label(udt.calling_ssn),
                ssn_label(udt.called_ssn)
            );
            // The called subsystem names the application the data belongs to,
            // so it selects the next dissector. Fall back to TCAP, which is
            // what the mobile-core subsystems (HLR, VLR, MSC) all carry.
            if let Some(mut inner) =
                dissect_subsystem(udt.called_ssn, src_ip, dst_ip, src_port, dst_port, udt.data)
            {
                inner.summary = format!("{} — {route}", inner.summary);
                return inner;
            }
            if let Some(inner) = super::tcap::describe(udt.data) {
                return DissectedResult {
                    src_addr: src_ip,
                    dst_addr: dst_ip,
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    protocol: Protocol::Tcap,
                    summary: format!("{inner} — {route}"),
                };
            }
            fallback(format!("SCCP {name} — {route}"))
        }
        None => fallback(format!("SCCP {name}")),
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Build a UDT message addressed between two subsystem numbers.
    pub fn udt(calling_ssn: u8, called_ssn: u8, data: &[u8]) -> Vec<u8> {
        // Address parameter: indicator with the SSN bit set, then the SSN.
        let addr = |ssn: u8| vec![0x02, ssn];
        let called = addr(called_ssn);
        let calling = addr(calling_ssn);

        let mut p = vec![0x09, 0x00]; // UDT, protocol class 0
                                      // Three pointers follow at offsets 2, 3, 4. Each is relative to itself,
                                      // so the first parameter starts 3 bytes past the first pointer.
        let ptr_called = 3u8;
        let ptr_calling = ptr_called + (1 + called.len() as u8) - 1;
        let ptr_data = ptr_calling + (1 + calling.len() as u8) - 1;
        p.push(ptr_called);
        p.push(ptr_calling);
        p.push(ptr_data);
        p.push(called.len() as u8);
        p.extend_from_slice(&called);
        p.push(calling.len() as u8);
        p.extend_from_slice(&calling);
        p.push(data.len() as u8);
        p.extend_from_slice(data);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::udt;
    use super::*;

    #[test]
    fn udt_reports_both_subsystems() {
        // Data that TCAP will not claim, so the SCCP summary is what shows.
        let p = udt(8, 6, &[0xFF, 0x00]);
        let r = dissect_sccp(None, None, 2905, 2905, &p);
        assert_eq!(r.protocol, Protocol::Sccp);
        assert_eq!(r.summary, "SCCP UDT — MSC → HLR");
    }

    #[test]
    fn unknown_subsystems_show_their_numbers() {
        let p = udt(200, 201, &[0xFF]);
        let r = dissect_sccp(None, None, 2905, 2905, &p);
        assert_eq!(r.summary, "SCCP UDT — SSN 200 → SSN 201");
    }

    #[test]
    fn parses_pointers_relative_to_themselves() {
        let p = udt(7, 6, b"payload");
        let parsed = parse_udt(&p).expect("UDT should parse");
        assert_eq!(parsed.calling_ssn, Some(7));
        assert_eq!(parsed.called_ssn, Some(6));
        assert_eq!(parsed.data, b"payload");
    }

    /// The address indicator says whether a point code precedes the subsystem
    /// number; reading the wrong offset would yield a plausible wrong SSN.
    #[test]
    fn ssn_is_read_past_the_point_code_when_present() {
        // Indicator 0x03: point code present + SSN present.
        let addr = [0x03, 0x11, 0x22, 6];
        assert_eq!(address_ssn(&addr), Some(6));
        // Indicator 0x02: SSN only.
        assert_eq!(address_ssn(&[0x02, 6]), Some(6));
        // Indicator 0x01: point code only, no SSN to read.
        assert_eq!(address_ssn(&[0x01, 0x11, 0x22]), None);
    }

    #[test]
    fn connection_oriented_types_are_named_without_addresses() {
        let r = dissect_sccp(None, None, 2905, 2905, &[0x01, 0x00, 0x00]);
        assert_eq!(r.summary, "SCCP CR");
    }

    #[test]
    fn truncated_and_empty_input_does_not_panic() {
        assert_eq!(dissect_sccp(None, None, 1, 2, &[]).summary, "SCCP (empty)");
        // A UDT whose pointers run past the buffer.
        let r = dissect_sccp(None, None, 1, 2, &[0x09, 0x00, 0xFF, 0xFF, 0xFF]);
        assert_eq!(r.summary, "SCCP UDT");
    }

    /// Subsystem 142 is RANAP, so the packet should be reported as RANAP.
    #[test]
    fn called_subsystem_selects_the_dissector() {
        let ranap = [0x00, 19, 0x00, 0x00]; // initiating InitialUE-Message
        let p = udt(8, 142, &ranap);
        let r = dissect_sccp(None, None, 2905, 2905, &p);
        assert_eq!(r.protocol, Protocol::Ranap);
        assert_eq!(r.summary, "RANAP InitialUE-Message — MSC → RANAP");
    }

    #[test]
    fn bssap_subsystem_is_dispatched() {
        let bssap = [0x00, 0x08, 0x52, 0x00]; // BSSMAP PAGING
        let p = udt(8, 255, &bssap);
        let r = dissect_sccp(None, None, 2905, 2905, &p);
        assert_eq!(r.protocol, Protocol::Bssap);
        assert_eq!(r.summary, "BSSMAP PAGING — MSC → BSSAP");
    }

    /// A subsystem with no dedicated dissector still reaches TCAP, which is
    /// what the mobile-core subsystems carry.
    #[test]
    fn core_subsystems_still_fall_through_to_tcap() {
        let tcap = crate::dissectors::tcap::test_helpers::tcap_invoke(0x62, 2);
        let p = udt(8, 6, &tcap);
        let r = dissect_sccp(None, None, 2905, 2905, &p);
        assert_eq!(r.protocol, Protocol::Tcap);
        assert_eq!(r.summary, "TCAP Begin Invoke — updateLocation — MSC → HLR");
    }

    #[test]
    fn unknown_message_type_reports_its_byte() {
        let r = dissect_sccp(None, None, 1, 2, &[0x7F, 0x00]);
        assert_eq!(r.summary, "SCCP message 0x7f");
    }
}
