// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{
    aeron, bindings, dht, dns, dtls, j1708, lorawan, mdns, memberlist, mpegts, openvpn, osc, qpack,
    rgoose, roughtime, rtp, rtps, source_query, srt_transport, turn, utp, vxlan, wol, zrtp,
    DissectedResult,
};

pub fn dissect_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let header = match etherparse::UdpHeader::from_slice(payload) {
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

    let (udp, udp_payload) = header;
    let src_port = udp.source_port;
    let dst_port = udp.destination_port;
    let on = |p: u16| src_port == p || dst_port == p;

    // 1. Ports whose dissector needs more than the standard call — a relabel
    //    on top of a shared wire format, a service-response time to record, or
    //    an extra argument. See `bindings` for the full precedence order.
    if on(53) {
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        if let Some(dur) = super::srt::record_dns(src_ip, dst_ip, src_port, dst_port, udp_payload) {
            r.summary = format!("{} [SRT: {:.1}ms]", r.summary, dur.as_secs_f64() * 1000.0);
        }
        return r;
    }
    if on(5353) {
        // mDNS shares the DNS wire format, but relabelling a DNS summary wastes
        // what makes it useful: the names carry a device's own description of
        // itself, and splitting them back into instance and service turns a
        // record into "Kitchen Speaker (AirPlay)".
        return mdns::dissect_mdns(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(5355) {
        // LLMNR uses the DNS wire format; reuse the DNS dissector, then relabel.
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
    // 102 is the OSI transport port, which carries more than R-GOOSE — so the
    // session identifier has to agree before a trip message is claimed.
    if on(102) && rgoose::looks_like_rgoose(udp_payload) {
        return rgoose::dissect_rgoose(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

    // 2. Exact well-known port.
    if let Some(dissect) = bindings::udp(src_port, dst_port) {
        return dissect(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }

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
    // Wake-on-LAN magic packets are sent to assorted UDP ports (7/9/…), so match
    // the unmistakable payload rather than a port.
    if wol::looks_like_wol(udp_payload) {
        return wol::dissect_wol(udp_payload);
    }
    // Broadcast video picks whatever multicast port the operator chose, so
    // both of these are recognised by their framing. MPEG-TS goes first: its
    // check is the stricter of the two (every 188-byte boundary must carry the
    // sync byte), so it cannot be shadowed by a looser test.
    if mpegts::looks_like_mpegts(udp_payload) {
        return mpegts::dissect_mpegts(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if srt_transport::looks_like_srt(udp_payload) {
        return srt_transport::dissect_srt_transport(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            udp_payload,
        );
    }
    // BitTorrent picks a port per client and changes it freely, so µTP is
    // recognised by its header: the version nibble must be exactly 1 and the
    // type at most 4, which no printable first byte satisfies.
    if utp::looks_like_utp(udp_payload) {
        return utp::dissect_utp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Roughtime deployments differ on which port they use, and the framed
    // form carries a magic string that identifies it unambiguously.
    if roughtime::looks_like_roughtime(udp_payload) {
        return roughtime::dissect_roughtime(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // 1700 is the Semtech packet forwarder's convention rather than an
    // assignment, and it wraps the radio frame in its own JSON envelope on some
    // paths — so the framing has to agree before the flow is claimed.
    if on(1700) && lorawan::looks_like_lorawan(udp_payload) {
        return lorawan::dissect_lorawan(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // OSC has no assigned port at all — every application picks its own — so a
    // capture filtered by port finds none of it. The shape is exact enough to
    // key on instead: an address pattern starting with a slash, or a bundle
    // tag, with everything padded to a multiple of four bytes.
    if osc::looks_like_osc(udp_payload) {
        return osc::dissect_osc(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // DTLS rides dynamically negotiated ports (WebRTC/VPN media), so recognise
    // it structurally from its record header before falling through to plugins.
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
    // J1708 has no magic and a weak two's-complement checksum. To avoid claiming
    // random short UDP payloads, it is tried last after all other candidates.
    if j1708::looks_like_j1708(udp_payload) {
        return j1708::dissect_j1708(udp_payload);
    }
    // ZRTP negotiates SRTP keys inside the media stream; its magic cookie sits
    // where RTP would put a timestamp.
    if zrtp::looks_like_zrtp(udp_payload) {
        return zrtp::dissect_zrtp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // TURN relays share STUN's ports but use a disjoint channel-number range.
    if turn::looks_like_turn(udp_payload) {
        return turn::dissect_turn(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // User-defined plugins claim what no built-in dissector recognised
    // (see crate::plugins) — they never shadow the protocols above.
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
    // RTP/RTCP media rides dynamically negotiated ports, so it has no well-known
    // port to key on — recognise it structurally, after user plugins have had
    // their say (ROADMAP §3.6).
    if let Some(r) = rtp::try_dissect(src_ip, dst_ip, src_port, dst_port, udp_payload) {
        return r;
    }

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Udp,
        summary: format!("UDP — {} bytes of payload", udp_payload.len()),
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

    #[test]
    fn udp_basic() {
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 30000, 40000, b"Hello");
        let ip_data = &data[14..];
        let (_src, _dst, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Udp);
        assert_eq!(result.src_port, Some(30000));
        assert_eq!(result.dst_port, Some(40000));
        assert!(result.summary.contains("5 bytes of payload"));
    }

    #[test]
    fn udp_dns_query_port() {
        // DNS query to port 53 should dispatch to DNS dissector
        let dns_payload = crate::dissectors::test_helpers::build_dns_query("example.com", 1234);
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 54321, 53, &dns_payload);
        let ip_data = &data[14..];
        let (_src, _dst, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Dns);
        assert!(result.summary.contains("example.com"));
    }

    /// AFS spreads its services across ten ports, and every one of them has to
    /// reach the dissector — the port is what names the server.
    #[test]
    fn udp_rx_dispatches_across_the_afs_port_block() {
        let mut rx = vec![0u8; 20];
        rx.push(1); // data packet
        rx.push(0x01); // client initiated
        rx.extend_from_slice(&[0u8; 6]);

        for port in 7000u16..=7009 {
            let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40000, port, &rx);
            let (_s, _d, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(&data[14..]);
            let result = dissect_udp(
                Some("10.0.0.1".parse().unwrap()),
                Some("10.0.0.2".parse().unwrap()),
                &udp_data,
            );
            assert_eq!(
                result.protocol,
                Protocol::Rx,
                "port {port} did not dispatch"
            );
        }
    }

    #[test]
    fn udp_malformed() {
        let result = dissect_udp(None, None, &[0; 3]);
        assert_eq!(result.protocol, Protocol::Unknown("malformed UDP".into()));
    }

    #[test]
    fn udp_quic_qpack() {
        let payload = vec![0x40, 0x00, 0x00, 0x82];
        let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, &payload);
        let ip_data = &data[14..];
        let (_src, _dst, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Quic);
        assert!(result.summary.contains("HTTP/3 :method: GET"));
    }
}
