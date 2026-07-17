// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{
    bacnet, bfd, coap, dhcp, dhcpv6, dnp3, dns, dtls, enip, glbp, gtp, hsrp, kerberos, l2tp, mgcp,
    nbds, nbns, netflow, ntp, openvpn, qpack, radius, rip, rmcp, rtp, sflow, sip, snmp, ssdp, stun,
    syslog, tftp, vxlan, wccp, wireguard, wol, wsd, DissectedResult,
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

    // Dispatch application-layer protocols by well-known port.
    if on(53) {
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        if let Some(dur) = super::srt::record_dns(src_ip, dst_ip, src_port, dst_port, udp_payload) {
            r.summary = format!("{} [SRT: {:.1}ms]", r.summary, dur.as_secs_f64() * 1000.0);
        }
        return r;
    }
    if on(5353) {
        // mDNS uses the DNS wire format; reuse the DNS dissector, then relabel.
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        r.protocol = Protocol::Mdns;
        r.summary = format!("mDNS — {}", r.summary.trim_start_matches("DNS ").trim());
        return r;
    }
    if on(67) || on(68) {
        return dhcp::dissect_dhcp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(123) {
        return ntp::dissect_ntp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(161) || on(162) {
        return snmp::dissect_snmp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(5060) || on(5061) {
        return sip::dissect_sip(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Industrial / OT protocols carried over UDP (ROADMAP §3.5).
    if on(47808) {
        return bacnet::dissect_bacnet(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(20000) {
        return dnp3::dissect_dnp3(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(2222) || on(44818) {
        return enip::dissect_enip(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Security / auth / VPN protocols (ROADMAP §3.7).
    if on(88) {
        return kerberos::dissect_kerberos(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(1812) || on(1813) || on(1645) || on(1646) {
        return radius::dissect_radius(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(1194) {
        return openvpn::dissect_openvpn(src_ip, dst_ip, src_port, dst_port, udp_payload, false);
    }
    if on(51820) {
        return wireguard::dissect_wireguard(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // IoT messaging (ROADMAP §3.8).
    if on(5683) {
        return coap::dissect_coap(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Infrastructure / discovery / logging services carried over UDP.
    if on(514) {
        return syslog::dissect_syslog(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(69) {
        return tftp::dissect_tftp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(1900) {
        return ssdp::dissect_ssdp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(3478) || on(3479) {
        return stun::dissect_stun(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(5355) {
        // LLMNR uses the DNS wire format; reuse the DNS dissector, then relabel.
        let mut r = dns::dissect_dns(src_ip, dst_ip, src_port, dst_port, udp_payload);
        r.protocol = Protocol::Llmnr;
        r.summary = format!("LLMNR — {}", r.summary.trim_start_matches("DNS ").trim());
        return r;
    }
    if on(546) || on(547) {
        return dhcpv6::dissect_dhcpv6(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(520) {
        return rip::dissect_rip(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(137) {
        return nbns::dissect_nbns(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Tunnelling, mobile-core and out-of-band management over UDP.
    if on(1701) {
        return l2tp::dissect_l2tp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(2152) || on(2123) {
        return gtp::dissect_gtp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(623) {
        return rmcp::dissect_rmcp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(3702) {
        return wsd::dissect_wsd(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Flow telemetry and router liveness/redundancy.
    if on(2055) || on(4739) || on(9995) {
        return netflow::dissect_netflow(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(6343) {
        return sflow::dissect_sflow(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(3784) {
        return bfd::dissect_bfd(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(1985) {
        return hsrp::dissect_hsrp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    // Cisco load-balancing, web-cache redirection, VoIP gateway control and
    // legacy NetBIOS datagrams.
    if on(3222) {
        return glbp::dissect_glbp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(2048) {
        return wccp::dissect_wccp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(2427) || on(2727) {
        return mgcp::dissect_mgcp(src_ip, dst_ip, src_port, dst_port, udp_payload);
    }
    if on(138) {
        return nbds::dissect_nbds(src_ip, dst_ip, src_port, dst_port, udp_payload);
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
    // DTLS rides dynamically negotiated ports (WebRTC/VPN media), so recognise
    // it structurally from its record header before falling through to plugins.
    if dtls::looks_like_dtls(udp_payload) {
        return dtls::dissect_dtls(src_ip, dst_ip, src_port, dst_port, udp_payload);
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
        summary: format!("QUIC — {phase}, {} bytes", payload.len()),
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
