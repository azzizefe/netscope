// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
//! UDP, and choosing what is inside it.
//!
//! The precedence here matches [`super::tcp`], and for the same reason: a
//! well-known port is stronger evidence than a payload that merely *looks* a
//! certain way, so ports are tried first and structural sniffs last. UDP leans
//! on the sniffs far more heavily than TCP does — media, overlay and
//! peer-to-peer protocols negotiate their ports at runtime, so there is often
//! no port to bind at all.
//!
//! 1. **Ports needing more than a lookup** — two protocols sharing a port, a
//!    service-response time to record, or an extra argument to pass.
//! 2. **Exact well-known port** — the [`bindings::udp`] table.
//! 3. **Framing on an expected port** — QUIC and VXLAN, where the port narrows
//!    the search and the header confirms it.
//! 4. **Framing alone** — ordered by how decisive the check is, strongest
//!    first, so a loose test can never shadow a magic number.
//! 5. **User plugins**, which never shadow a built-in.

use std::net::IpAddr;

use crate::models::Protocol;

use super::{
    aeron, bindings, dht, dns, dtls, j1708, lorawan, memberlist, openvpn, osc, qpack, rtp, rtps,
    source_query, vxlan, wol, zrtp, DissectedResult,
};

pub fn dissect_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let (udp, udp_payload) = match etherparse::UdpHeader::from_slice(payload) {
        Ok((h, rest)) => (h, rest),
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown("malformed UDP".into()),
                summary: "Malformed UDP header".into(),
            };
        }
    };

    let src_port = udp.source_port;
    let dst_port = udp.destination_port;
    let on = |p: u16| src_port == p || dst_port == p;

    // 1. Ports whose dissector needs more than the standard call.
    if on(53) {
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        if let Some(dur) = super::srt::record_dns(src_ip, dst_ip, src_port, dst_port, udp_payload) {
            r.summary = format!("{} [SRT: {:.1}ms]", r.summary, dur.as_secs_f64() * 1000.0);
        }
        return r;
    }
    if on(5355) {
        // LLMNR is the DNS wire format on its own port; reuse the decoder and
        // relabel, rather than keeping a second copy of it.
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        r.protocol = Protocol::Llmnr;
        r.summary = format!("LLMNR — {}", r.summary.trim_start_matches("DNS ").trim());
        return r;
    }
    if on(1194) {
        // OpenVPN shares a port number across TCP and UDP; the flag says which.
        return openvpn::dissect_openvpn(src_ip, dst_ip, src_port, dst_port, udp_payload, false);
    }
    // 7946 is Serf's convention rather than an assignment, and the same port
    // carries a TCP stream for the bulk state sync, so the framing has to agree
    // before the flow is claimed.
    if on(7946) && memberlist::looks_like_memberlist(udp_payload) {
        return memberlist::dissect_memberlist(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

    // 2. Exact well-known port.
    if let Some(dissect) = bindings::udp(src_port, dst_port) {
        return dissect(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

    // 3. Framing on a port that narrows the search.
    if (on(443) || on(80)) && looks_like_quic(udp_payload) {
        return quic_result(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // VXLAN overlay tunnels (Kubernetes, OpenStack, DC fabrics). Falls through
    // to the generic UDP summary when the header doesn't validate.
    if vxlan::VXLAN_PORTS.iter().any(|&p| on(p)) {
        if let Some(r) = vxlan::dissect_vxlan(src_ip, dst_ip, src_port, dst_port, udp_payload) {
            return r;
        }
    }
    // 1700 is the Semtech packet forwarder's convention rather than an
    // assignment, and it wraps the radio frame in its own JSON envelope on some
    // paths — so the framing has to agree before the flow is claimed.
    if on(1700) && lorawan::looks_like_lorawan(udp_payload) {
        return lorawan::dissect_lorawan(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

    // 4. Framing alone, strongest check first.
    // Wake-on-LAN magic packets are sent to assorted ports (7/9/…), so match
    // the unmistakable payload rather than a port.
    if wol::looks_like_wol(udp_payload) {
        return wol::dissect_wol(udp_payload);
    }
    // OSC has no assigned port at all — every application picks its own — so a
    // capture filtered by port finds none of it. The shape is exact enough to
    // key on instead: an address pattern starting with a slash, or a bundle
    // tag, with everything padded to a multiple of four bytes.
    if osc::looks_like_osc(udp_payload) {
        return osc::dissect_osc(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // DTLS rides dynamically negotiated ports (WebRTC/VPN media), so recognise
    // it structurally from its record header.
    if dtls::looks_like_dtls(udp_payload) {
        return dtls::dissect_dtls(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // RTPS/DDS uses dynamic ports; recognise it by its "RTPS" magic.
    if rtps::looks_like_rtps(udp_payload) {
        return rtps::dissect_rtps(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Aeron's ports are chosen per deployment, so it is recognised by its
    // header alone: the only defined version, a listed frame type, and an
    // aligned length that agrees with the datagram. That is weaker evidence
    // than a magic, so it is tried *after* every protocol that has one — it
    // claimed a DTLS record when it ran earlier.
    if aeron::looks_like_aeron(udp_payload) {
        return aeron::dissect_aeron(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // BitTorrent DHT and Source-engine queries also ride arbitrary UDP ports.
    if dht::looks_like_dht(udp_payload) {
        return dht::dissect_dht(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if source_query::looks_like_source(udp_payload) {
        return source_query::dissect_source_query(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // ZRTP negotiates SRTP keys inside the media stream; its magic cookie sits
    // where RTP would put a timestamp, so it must be tried before RTP.
    if zrtp::looks_like_zrtp(udp_payload) {
        return zrtp::dissect_zrtp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // J1708 has no magic and a weak two's-complement checksum. To avoid
    // claiming random short payloads, it is tried after every other candidate.
    if j1708::looks_like_j1708(udp_payload) {
        return j1708::dissect_j1708(udp_payload);
    }

    // 5. User-defined plugins claim what no built-in dissector recognised
    //    (see crate::plugins) — they never shadow the protocols above.
    if let Some(p) = crate::plugins::try_dissect(
        crate::plugins::TransportKind::Udp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        udp_payload,
    ) {
        return p;
    }
    // RTP/RTCP media rides dynamically negotiated ports, so it has no
    // well-known port to key on — recognise it structurally, after user plugins
    // have had their say (ROADMAP §3.6).
    if let Some(r) = rtp::try_dissect(src_ip, dst_ip, src_port, dst_port, udp_payload) {
        return r;
    }

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Udp,
        summary: format!(
            "UDP — {} of payload",
            super::bytes(udp_payload.len() as u64)
        ),
    }
}

/// Heuristic QUIC detection. QUIC's first byte has the "fixed bit" (0x40) set;
/// long-header packets (Initial/Handshake/0-RTT/Retry) also set the high bit
/// (0x80) and carry a 4-byte version. This is a heuristic, not a full parse —
/// it only runs on UDP 443/80 where QUIC is expected.
fn looks_like_quic(payload: &[u8]) -> bool {
    match payload.first() {
        // Long header: high bit + fixed bit set, plus room for the version.
        Some(b) if b & 0x80 != 0 && b & 0x40 != 0 => payload.len() >= 5,
        // Short header (1-RTT): fixed bit set, high bit clear.
        Some(b) if b & 0x40 != 0 => !payload.is_empty(),
        _ => false,
    }
}

fn quic_result(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let first = payload[0];
    let mut phase = if first & 0x80 == 0 {
        "1-RTT".to_string()
    } else {
        // Long-header packet-type bits (0x30) name the handshake phase.
        let kind = match (first & 0x30) >> 4 {
            0x0 => "Initial",
            0x1 => "0-RTT",
            0x2 => "Handshake",
            0x3 => "Retry",
            _ => "long-header",
        };
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if version == 0 {
            "Version Negotiation".to_string()
        } else {
            format!("{kind} (v0x{version:08x})")
        }
    };

    if let Some(headers) = qpack::decode_qpack(payload) {
        let h_str: Vec<String> = headers.iter().map(|(n, v)| format!("{n}: {v}")).collect();
        phase = format!("{phase} (HTTP/3 {})", h_str.join(", "));
    }

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Quic,
        summary: format!("QUIC — {phase}, {}", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::build_udp_packet;

    /// Run the dissector over a built test frame, past its Ethernet and IPv4
    /// headers.
    fn run(data: &[u8]) -> DissectedResult {
        let (_s, _d, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(&data[14..]);
        dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        )
    }

    #[test]
    fn a_payload_on_no_known_port_stays_udp() {
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 30000, 40000, b"Hello");
        let result = run(&data);
        assert_eq!(result.protocol, Protocol::Udp);
        assert_eq!(result.src_port, Some(30000));
        assert_eq!(result.dst_port, Some(40000));
        assert_eq!(result.summary, "UDP — 5 bytes of payload");
    }

    /// The reason step 2 exists: a table row has to actually be reached.
    #[test]
    fn a_well_known_port_reaches_its_dissector() {
        let dns = crate::dissectors::test_helpers::build_dns_query("example.com", 1234);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns);
        let result = run(&data);
        assert_eq!(result.protocol, Protocol::Dns);
        assert!(result.summary.contains("example.com"), "{}", result.summary);
    }

    /// A protocol with no port at all is found by its framing — this is what
    /// step 4 is for, and most of UDP depends on it.
    #[test]
    fn a_portless_protocol_is_found_by_its_framing() {
        let mut dtls = vec![22, 0xFE, 0xFD, 0x00, 0x00];
        dtls.extend_from_slice(&[0u8; 8]);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 50001, &dtls);
        assert_eq!(run(&data).protocol, Protocol::Dtls);
    }

    #[test]
    fn a_truncated_header_is_reported_not_guessed() {
        let result = dissect_udp(None, None, &[0; 3]);
        assert_eq!(result.protocol, Protocol::Unknown("malformed UDP".into()));
        assert_eq!(result.src_port, None);
    }
}
