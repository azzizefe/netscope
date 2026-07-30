// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// GTPv2-C message types (3GPP TS 29.274 §6.1). These are the operations that
/// create and move a phone's data session through the mobile core.
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "Echo Request",
        2 => "Echo Response",
        3 => "Version Not Supported Indication",
        32 => "Create Session Request",
        33 => "Create Session Response",
        34 => "Modify Bearer Request",
        35 => "Modify Bearer Response",
        36 => "Delete Session Request",
        37 => "Delete Session Response",
        38 => "Change Notification Request",
        39 => "Change Notification Response",
        64 => "Modify Bearer Command",
        65 => "Modify Bearer Failure Indication",
        66 => "Delete Bearer Command",
        67 => "Delete Bearer Failure Indication",
        68 => "Bearer Resource Command",
        69 => "Bearer Resource Failure Indication",
        70 => "Downlink Data Notification Failure Indication",
        71 => "Trace Session Activation",
        72 => "Trace Session Deactivation",
        73 => "Stop Paging Indication",
        95 => "Create Bearer Request",
        96 => "Create Bearer Response",
        97 => "Update Bearer Request",
        98 => "Update Bearer Response",
        99 => "Delete Bearer Request",
        100 => "Delete Bearer Response",
        101 => "Delete PDN Connection Set Request",
        102 => "Delete PDN Connection Set Response",
        103 => "PGW Downlink Triggering Notification",
        104 => "PGW Downlink Triggering Acknowledge",
        128 => "Identification Request",
        129 => "Identification Response",
        130 => "Context Request",
        131 => "Context Response",
        132 => "Context Acknowledge",
        133 => "Forward Relocation Request",
        134 => "Forward Relocation Response",
        135 => "Forward Relocation Complete Notification",
        136 => "Forward Relocation Complete Acknowledge",
        137 => "Forward Access Context Notification",
        138 => "Forward Access Context Acknowledge",
        139 => "Relocation Cancel Request",
        140 => "Relocation Cancel Response",
        141 => "Configuration Transfer Tunnel",
        149 => "Detach Notification",
        150 => "Detach Acknowledge",
        151 => "CS Paging Indication",
        152 => "RAN Information Relay",
        153 => "Alert MME Notification",
        154 => "Alert MME Acknowledge",
        155 => "UE Activity Notification",
        156 => "UE Activity Acknowledge",
        160 => "Create Forwarding Tunnel Request",
        161 => "Create Forwarding Tunnel Response",
        162 => "Suspend Notification",
        163 => "Suspend Acknowledge",
        164 => "Resume Notification",
        165 => "Resume Acknowledge",
        166 => "Create Indirect Data Forwarding Tunnel Request",
        167 => "Create Indirect Data Forwarding Tunnel Response",
        168 => "Delete Indirect Data Forwarding Tunnel Request",
        169 => "Delete Indirect Data Forwarding Tunnel Response",
        170 => "Release Access Bearers Request",
        171 => "Release Access Bearers Response",
        176 => "Downlink Data Notification",
        177 => "Downlink Data Notification Acknowledge",
        179 => "PGW Restart Notification",
        180 => "PGW Restart Notification Acknowledge",
        200 => "Update PDN Connection Set Request",
        201 => "Update PDN Connection Set Response",
        211 => "Modify Access Bearers Request",
        212 => "Modify Access Bearers Response",
        _ => return None,
    })
}

/// Dissect a GTPv2-C message — the LTE/5G control plane that creates and moves
/// a phone's data session, on UDP 2123 (3GPP TS 29.274).
///
/// The header is a flags byte (version, plus bits saying whether the optional
/// TEID and message-priority fields are present), the message type, a length,
/// then optionally the tunnel endpoint identifier, then a 3-byte sequence
/// number. Version 1 is a different protocol entirely and is handled by the
/// `gtp` dissector.
pub fn dissect_gtpv2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = dissect_summary(payload);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gtpv2,
        summary,
    }
}

fn dissect_summary(payload: &[u8]) -> String {
    // Flags, type and length are the minimum 4 bytes of any GTPv2 header.
    if payload.len() < 4 {
        return format!("GTPv2-C ({})", super::bytes(payload.len() as u64));
    }
    let flags = payload[0];
    let version = flags >> 5;
    if version != 2 {
        return format!("GTPv2-C (unexpected version {version})");
    }
    let msg_type = payload[1];
    let name = match message_name(msg_type) {
        Some(n) => n.to_string(),
        None => format!("message {msg_type}"),
    };
    // The T flag says whether a 4-byte tunnel endpoint identifier follows the
    // length. It is absent on the messages that are not tied to one session
    // yet, such as an Echo or an initial Create Session Request.
    let has_teid = flags & 0x08 != 0;
    if has_teid && payload.len() >= 12 {
        let teid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let seq = u32::from_be_bytes([0, payload[8], payload[9], payload[10]]);
        format!("GTPv2-C {name} — TEID 0x{teid:08x}, seq {seq}")
    } else if !has_teid && payload.len() >= 8 {
        let seq = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
        format!("GTPv2-C {name} — seq {seq}")
    } else {
        format!("GTPv2-C {name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a GTPv2-C header. `teid` present sets the T flag.
    fn gtpv2(msg_type: u8, teid: Option<u32>, seq: u32) -> Vec<u8> {
        let mut p = Vec::new();
        let flags = 0x40 | if teid.is_some() { 0x08 } else { 0 };
        p.push(flags);
        p.push(msg_type);
        p.extend_from_slice(&0u16.to_be_bytes()); // length, not used by the summary
        if let Some(t) = teid {
            p.extend_from_slice(&t.to_be_bytes());
        }
        p.extend_from_slice(&seq.to_be_bytes()[1..]); // 3-byte sequence number
        p.push(0); // spare
        p
    }

    #[test]
    fn create_session_request_with_teid() {
        let p = gtpv2(32, Some(0xdeadbeef), 42);
        let r = dissect_gtpv2(None, None, 2123, 2123, &p);
        assert_eq!(r.protocol, Protocol::Gtpv2);
        assert_eq!(
            r.summary,
            "GTPv2-C Create Session Request — TEID 0xdeadbeef, seq 42"
        );
    }

    #[test]
    fn echo_request_has_no_teid() {
        let p = gtpv2(1, None, 7);
        let r = dissect_gtpv2(None, None, 2123, 2123, &p);
        assert_eq!(r.summary, "GTPv2-C Echo Request — seq 7");
    }

    #[test]
    fn delete_session_response() {
        let p = gtpv2(37, Some(1), 100);
        let r = dissect_gtpv2(None, None, 2123, 2123, &p);
        assert_eq!(
            r.summary,
            "GTPv2-C Delete Session Response — TEID 0x00000001, seq 100"
        );
    }

    /// GTPv1 shares the port range in some deployments; refusing to decode it
    /// as v2 keeps the two from being confused.
    #[test]
    fn version_one_is_not_claimed() {
        let p = vec![0x30, 0x01, 0x00, 0x00];
        let r = dissect_gtpv2(None, None, 2123, 2123, &p);
        assert_eq!(r.summary, "GTPv2-C (unexpected version 1)");
    }

    #[test]
    fn unknown_type_reports_its_number() {
        let p = gtpv2(250, None, 1);
        let r = dissect_gtpv2(None, None, 2123, 2123, &p);
        assert_eq!(r.summary, "GTPv2-C message 250 — seq 1");
    }

    #[test]
    fn truncated_header_does_not_panic() {
        let r = dissect_gtpv2(None, None, 2123, 2123, &[0x48]);
        assert_eq!(r.summary, "GTPv2-C (1 byte)");
    }
}
