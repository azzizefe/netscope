// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an APRS-IS message (TCP 14580) — the internet backbone of the
/// amateur-radio Automatic Packet Reporting System, carrying position and
/// telemetry beacons as text.
pub fn dissect_aprs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("user ") {
        format!("APRS-IS login — {}", super::truncate(&line, 40))
    } else if line.starts_with('#') {
        format!("APRS-IS server comment — {}", super::truncate(&line, 40))
    } else if let Some((call, _)) = line.split_once('>') {
        format!("APRS-IS packet from {}", super::truncate(call, 24))
    } else {
        format!("APRS-IS ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Aprs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon() {
        let r = dissect_aprs(
            None,
            None,
            14580,
            40000,
            b"TA1ABC>APRS,TCPIP*:=4100.00N/02900.00E-\r\n",
        );
        assert_eq!(r.protocol, Protocol::Aprs);
        assert_eq!(r.summary, "APRS-IS packet from TA1ABC");
    }

    #[test]
    fn login() {
        let r = dissect_aprs(
            None,
            None,
            40000,
            14580,
            b"user TA1ABC pass -1 vers netscope 1.0\r\n",
        );
        assert!(r.summary.starts_with("APRS-IS login"), "{}", r.summary);
    }
}
