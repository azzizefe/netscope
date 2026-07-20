// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// DLMS APDU tags (DLMS/COSEM Green Book, §A.2). The `glo-` forms are the same
/// operations with the body encrypted — which one is used tells you whether the
/// meter's data is protected on the wire.
fn apdu_name(tag: u8) -> Option<(&'static str, bool)> {
    // (name, ciphered)
    Some(match tag {
        0x01 => ("InitiateRequest", false),
        0x08 => ("InitiateResponse", false),
        0x05 => ("ReadResponse", false),
        0x06 => ("WriteRequest", false),
        0x07 => ("WriteResponse", false),
        0x0E => ("ReadRequest", false),
        0x60 => ("AARQ (association request)", false),
        0x61 => ("AARE (association response)", false),
        0x62 => ("RLRQ (release request)", false),
        0x63 => ("RLRE (release response)", false),
        0xC0 => ("GET-Request", false),
        0xC1 => ("SET-Request", false),
        0xC3 => ("ACTION-Request", false),
        0xC4 => ("GET-Response", false),
        0xC5 => ("SET-Response", false),
        0xC7 => ("ACTION-Response", false),
        0xC8 => ("GET-Request", true),
        0xC9 => ("SET-Request", true),
        0xCB => ("ACTION-Request", true),
        0xCC => ("GET-Response", true),
        0xCD => ("SET-Response", true),
        0xCF => ("ACTION-Response", true),
        0x21 => ("InitiateRequest", true),
        0x28 => ("InitiateResponse", true),
        0xD8 => ("EventNotification", false),
        _ => return None,
    })
}

/// The wrapper that carries DLMS over TCP (Green Book §7.3.3): a version, a
/// source and destination "wPort" naming the logical devices, and a length.
const WRAPPER: usize = 8;
const WRAPPER_VERSION: u16 = 0x0001;

/// Dissect a DLMS/COSEM message — the protocol electricity, gas and water
/// meters use to report readings and be configured, on TCP 4059
/// (DLMS/COSEM Green Book).
///
/// Whether the body is encrypted is worth surfacing: an unciphered SET-Request
/// means a meter is being reconfigured in the clear.
pub fn dissect_dlms(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("DLMS ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dlms,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    // The wrapper is optional in principle, but is what TCP transport uses.
    let version = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    let (apdu, client, server) = if version == WRAPPER_VERSION && payload.len() > WRAPPER {
        let client = u16::from_be_bytes([payload[2], payload[3]]);
        let server = u16::from_be_bytes([payload[4], payload[5]]);
        (payload.get(WRAPPER..)?, Some(client), Some(server))
    } else {
        (payload, None, None)
    };

    let (name, ciphered) = apdu_name(*apdu.first()?)?;
    let route = match (client, server) {
        (Some(c), Some(s)) => format!(" — client {c} → server {s}"),
        _ => String::new(),
    };
    Some(if ciphered {
        format!("DLMS {name} (encrypted){route}")
    } else {
        format!("DLMS {name}{route}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wrapped DLMS message carrying one APDU tag.
    fn wrapped(client: u16, server: u16, tag: u8) -> Vec<u8> {
        let mut p = WRAPPER_VERSION.to_be_bytes().to_vec();
        p.extend_from_slice(&client.to_be_bytes());
        p.extend_from_slice(&server.to_be_bytes());
        p.extend_from_slice(&2u16.to_be_bytes()); // length
        p.push(tag);
        p.push(0x00);
        p
    }

    #[test]
    fn get_request_names_the_logical_devices() {
        let r = dissect_dlms(None, None, 40000, 4059, &wrapped(1, 17, 0xC0));
        assert_eq!(r.protocol, Protocol::Dlms);
        assert_eq!(r.summary, "DLMS GET-Request — client 1 → server 17");
    }

    #[test]
    fn association_setup_is_named() {
        let r = dissect_dlms(None, None, 40000, 4059, &wrapped(1, 17, 0x60));
        assert_eq!(
            r.summary,
            "DLMS AARQ (association request) — client 1 → server 17"
        );
    }

    /// Whether the body is encrypted is the security-relevant fact here: the
    /// same operation has a separate tag for its ciphered form.
    #[test]
    fn ciphered_apdus_are_marked() {
        let plain = dissect_dlms(None, None, 1, 4059, &wrapped(1, 17, 0xC1));
        assert_eq!(plain.summary, "DLMS SET-Request — client 1 → server 17");
        let ciphered = dissect_dlms(None, None, 1, 4059, &wrapped(1, 17, 0xC9));
        assert_eq!(
            ciphered.summary,
            "DLMS SET-Request (encrypted) — client 1 → server 17"
        );
    }

    /// The wrapper is what TCP transport adds; a bare APDU still decodes, just
    /// without the logical-device numbers.
    #[test]
    fn unwrapped_apdu_still_decodes() {
        let r = dissect_dlms(None, None, 1, 4059, &[0xC0, 0x01, 0x00]);
        assert_eq!(r.summary, "DLMS GET-Request");
    }

    #[test]
    fn event_notification_is_named() {
        let r = dissect_dlms(None, None, 4059, 40000, &wrapped(17, 1, 0xD8));
        assert_eq!(r.summary, "DLMS EventNotification — client 17 → server 1");
    }

    #[test]
    fn unknown_tag_is_not_claimed() {
        let r = dissect_dlms(None, None, 1, 4059, &wrapped(1, 17, 0x7E));
        assert_eq!(
            r.summary,
            format!("DLMS ({} bytes)", wrapped(1, 17, 0x7E).len())
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_dlms(None, None, 1, 4059, &[0x00, 0x01]);
        assert_eq!(r.summary, "DLMS (2 bytes)");
        let r = dissect_dlms(None, None, 1, 4059, &[]);
        assert_eq!(r.summary, "DLMS (0 bytes)");
    }
}
