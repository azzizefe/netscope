// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Syslog severity names, indexed by the low 3 bits of the PRI value (RFC 5424).
const SEVERITIES: [&str; 8] = [
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Info",
    "Debug",
];

/// Dissect a Syslog message (UDP 514). Every syslog line begins with a
/// `<PRI>` value that packs the facility (PRI / 8) and severity (PRI % 8);
/// the remainder is the free-form log text (RFC 3164 / RFC 5424).
pub fn dissect_syslog(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("Syslog message ({} bytes)", payload.len()));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Syslog,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&b'<') {
        return None;
    }
    let close = payload.iter().position(|&b| b == b'>')?;
    // PRI is 1–3 digits, so '>' sits at index 2..=4.
    if !(2..=4).contains(&close) {
        return None;
    }
    let pri: u16 = std::str::from_utf8(&payload[1..close]).ok()?.parse().ok()?;
    let facility = pri / 8;
    let sev = *SEVERITIES.get((pri % 8) as usize)?;
    let msg = super::truncate(&super::first_text_line(&payload[close + 1..]), 60);
    if msg.is_empty() {
        Some(format!("Syslog {sev} (facility {facility})"))
    } else {
        Some(format!("Syslog {sev} (facility {facility}) — {msg}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pri_severity_and_facility() {
        // <34> = facility 4 (auth), severity 2 (Critical).
        let r = dissect_syslog(None, None, 40000, 514, b"<34>Oct 11 22:14:15 host su: failed");
        assert_eq!(r.protocol, Protocol::Syslog);
        assert!(r.summary.starts_with("Syslog Critical (facility 4)"), "{}", r.summary);
        assert!(r.summary.contains("failed"));
    }

    #[test]
    fn non_syslog_payload_falls_back() {
        let r = dissect_syslog(None, None, 40000, 514, b"not a syslog line");
        assert_eq!(r.protocol, Protocol::Syslog);
        assert!(r.summary.contains("Syslog message"));
    }
}
