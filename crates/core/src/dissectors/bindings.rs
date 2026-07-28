// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Well-known port to dissector bindings.
//!
//! These used to be a linear `if src_port == N || dst_port == N` chain in
//! `tcp.rs` and `udp.rs` — around 600 lines, walked in full for every packet
//! that matched nothing. They are now sorted tables, looked up by binary
//! search, so the cost is logarithmic in the number of protocols rather than
//! linear.
//!
//! ## Dispatch precedence
//!
//! `tcp.rs` and `udp.rs` apply these in a deliberate order, most specific
//! first:
//!
//! 1. **Port plus a content guard** — a port that sits in the ephemeral range
//!    (DRDA on 50000, MySQL X on 33060) only claims a flow if the payload also
//!    carries the protocol's framing.
//! 2. **Exact port match** — this table.
//! 3. **Port ranges** — BitTorrent 6881-6889, X11 6000-6005, SOME/IP 30490-30510.
//! 4. **Structural sniffs** — protocols with no fixed port at all (SPICE, ZMTP,
//!    DTLS, RTP), recognised by their framing.
//! 5. **User plugins**, which never shadow a built-in.
//!
//! A well-known port therefore always beats a structural sniff. Adding a
//! protocol on a fixed port means adding a row here and nothing else.

use std::net::IpAddr;

use super::DissectedResult;
use super::{
    aerospike, afp, amqp, amt, b_r_automation_pvi, bacnet, beckhoff_twincat_analytics, bfcp, bfd,
    bgp, bosch_nexeed_edge, bosch_rexroth_open_core, capwap, cassandra, ccp, cip_safety, cmp, coap,
    dhcp, dhcp_failover, dhcpv6, dicom, dmx, dnp3, doip, e1ap, edge_inference_onnx,
    edge_tensorflow_lite, enip, epic_online_eos_p2p, f1ap, factorytalk_view_hmi, fanuc_focas2,
    finger, gelf, geneve, glbp, gopher, gtp, gtpprime, gvcp, h225ras, hl7, hnbap, hsrp, iax2,
    interbus, ipsec, isakmp, iscsi, isns, kerberos, kpasswd, l2tp, lcsap, ldap, ldp, lisp, m2ap,
    m2pa, m2ua, m3ap, m3ua, matter, mechatrolink, memcached, mitsubishi_melsec_proto, modbus,
    mongodb, mqtt, mqttsn, mssqlbrowser, mumble, mysql, nbap, nbds, nbns, netflow, ngap, ninep,
    nintendo_npln_p2p, nsip, ntp, omron_fins_udp_detail, opcua, openflow, p_net, pcp, pfcp,
    psn_matchmaking_v3, ptp, q931, radius, rdp, redis, rip, ripng, rockwell_factorytalk_edge, rpc,
    rpkirtr, rtpmidi, rtsp, rua, rwho, s1ap, s7comm_plus_detail, sabp, sbcap, sflow,
    siemens_industrial_edge, simatic_hmi_smartsrv, sinumerik_nck_channel, sip, snmp,
    steam_datagram_relay, studio5000_online_comm, stun, sua, syslog, tacacs,
    tia_portal_online_diag, tls, twincat_router_telemetry, twincat_scope_view, uadp, vxlangpe,
    wccp, wireguard, wsd, xbox_live_sdv2, xcp, xnap,
};

/// The signature every port-dispatched dissector shares.
pub type PortDissector = fn(Option<IpAddr>, Option<IpAddr>, u16, u16, &[u8]) -> DissectedResult;

/// Resolve a TCP port pair to its dissector.
///
/// The destination port is tried first: on a client-to-server segment that is
/// the service port, and on the reply the destination is the client's ephemeral
/// port, which has no binding, so the source port answers instead.
pub fn tcp(src_port: u16, dst_port: u16) -> Option<PortDissector> {
    lookup(TCP_PORTS, dst_port).or_else(|| lookup(TCP_PORTS, src_port))
}

/// Resolve a UDP port pair to its dissector. See [`tcp`] for the port order.
pub fn udp(src_port: u16, dst_port: u16) -> Option<PortDissector> {
    lookup(UDP_PORTS, dst_port).or_else(|| lookup(UDP_PORTS, src_port))
}

/// Resolve an SCTP payload protocol identifier to its dissector.
///
/// The 3GPP signalling protocols and the SIGTRAN adaptation layers all share
/// SCTP and are distinguished only by this identifier, not by port — an
/// operator is free to run NGAP on any port it likes, and often does.
/// Registered values are listed by IANA under "SCTP Payload Protocol
/// Identifiers".
pub fn sctp_ppid(ppid: u32) -> Option<PortDissector> {
    SCTP_PPIDS
        .binary_search_by_key(&ppid, |(p, _)| *p)
        .ok()
        .map(|i| SCTP_PPIDS[i].1)
}

/// SCTP payload protocol identifiers, sorted. See [`TCP_PORTS`].
static SCTP_PPIDS: &[(u32, PortDissector)] = &[
    (2, m2ua::dissect_m2ua),
    (3, m3ua::dissect_m3ua),
    (4, sua::dissect_sua),
    (5, m2pa::dissect_m2pa),
    (18, s1ap::dissect_s1ap),
    (19, rua::dissect_rua),
    (20, hnbap::dissect_hnbap),
    (24, sbcap::dissect_sbcap),
    (25, nbap::dissect_nbap),
    (29, lcsap::dissect_lcsap),
    (31, sabp::dissect_sabp),
    (43, m2ap::dissect_m2ap),
    (44, m3ap::dissect_m3ap),
    (60, ngap::dissect_ngap),
    (61, xnap::dissect_xnap),
    (62, f1ap::dissect_f1ap),
    (64, e1ap::dissect_e1ap),
];

fn lookup(table: &[(u16, PortDissector)], port: u16) -> Option<PortDissector> {
    table
        .binary_search_by_key(&port, |(p, _)| *p)
        .ok()
        .map(|i| table[i].1)
}

/// TCP service ports, sorted by port number so [`lookup`] can binary-search.
/// Keep it sorted — [`tables_are_sorted_and_unique`] enforces it.
static TCP_PORTS: &[(u16, PortDissector)] = &[
    // The 1980s debugging services. Nothing legitimate has used them in
    // decades, so seeing one at all is the finding — see `small_services`.
    (49, tacacs::dissect_tacacs),
    (70, gopher::dissect_gopher),
    (79, finger::dissect_finger),
    (88, kerberos::dissect_kerberos),
    (102, s7comm_plus_detail::dissect_s7comm_plus_detail),
    (104, dicom::dissect_dicom),
    (111, rpc::dissect_rpc),
    (179, bgp::dissect_bgp),
    (323, rpkirtr::dissect_rpkirtr),
    (389, ldap::dissect_ldap),
    (443, tls::dissect_tls),
    (464, kpasswd::dissect_kpasswd),
    (502, modbus::dissect_modbus),
    (548, afp::dissect_afp),
    (554, rtsp::dissect_rtsp),
    (564, ninep::dissect_9p),
    (646, ldp::dissect_ldp),
    (647, dhcp_failover::dissect_dhcp_failover),
    (829, cmp::dissect_cmp),
    (1720, q931::dissect_q931),
    (1883, mqtt::dissect_mqtt),
    (2020, sinumerik_nck_channel::dissect_sinumerik_nck_channel),
    (2049, rpc::dissect_rpc),
    (2575, hl7::dissect_hl7),
    (3000, aerospike::dissect_aerospike),
    // iSNS sits just below iSCSI's own port, and is where an initiator's
    // targets come from in the first place.
    (3205, isns::dissect_isns),
    (3238, bfcp::dissect_bfcp),
    (3260, iscsi::dissect_iscsi),
    (3306, mysql::dissect_mysql),
    (3389, rdp::dissect_rdp),
    (4121, interbus::dissect_interbus),
    (4410, tia_portal_online_diag::dissect_tia_portal_online_diag),
    (4840, opcua::dissect_opcua),
    (4841, studio5000_online_comm::dissect_studio5000_online_comm),
    (
        4860,
        siemens_industrial_edge::dissect_siemens_industrial_edge,
    ),
    (
        5007,
        mitsubishi_melsec_proto::dissect_mitsubishi_melsec_proto,
    ),
    (5672, amqp::dissect_amqp),
    (6002, factorytalk_view_hmi::dissect_factorytalk_view_hmi),
    (6379, redis::dissect_redis),
    (6653, openflow::dissect_openflow),
    (8001, edge_inference_onnx::dissect_edge_inference_onnx),
    (8087, twincat_scope_view::dissect_twincat_scope_view),
    (8090, simatic_hmi_smartsrv::dissect_simatic_hmi_smartsrv),
    (8193, fanuc_focas2::dissect_fanuc_focas2),
    (8501, edge_tensorflow_lite::dissect_edge_tensorflow_lite),
    (8910, bosch_nexeed_edge::dissect_bosch_nexeed_edge),
    (9042, cassandra::dissect_cassandra),
    (11112, dicom::dissect_dicom),
    (11157, b_r_automation_pvi::dissect_br_automation_pvi),
    (11211, memcached::dissect_memcached),
    (13400, doip::dissect_doip),
    (20001, dnp3::dissect_dnp3),
    (24007, rpc::dissect_rpc),
    (27017, mongodb::dissect_mongodb),
    (
        41100,
        bosch_rexroth_open_core::dissect_bosch_rexroth_open_core,
    ),
    (44818, enip::dissect_enip),
    (
        44819,
        rockwell_factorytalk_edge::dissect_rockwell_factorytalk_edge,
    ),
    (
        48400,
        beckhoff_twincat_analytics::dissect_beckhoff_twincat_analytics,
    ),
    (
        48899,
        twincat_router_telemetry::dissect_twincat_router_telemetry,
    ),
    // 51000/51001/51002 held `edge_pytorch_mobile`, `nxp_eiq_inference` and
    // `stm_stm32cube_ai`. All three are gone: the ports are invented — three
    // consecutive numbers in the middle of the Linux ephemeral range
    // (32768-60999) — and none of the three dissectors validates a single byte
    // before claiming the flow. This table matches source ports as well as
    // destination ports, so any ordinary outbound connection that happened to
    // be assigned 51000 came back labelled as PyTorch Mobile inference. A test
    // in tcp.rs pins this: 64 zero bytes on an ephemeral port is TCP.
    //
    // This is the rule in the precedence list at the top of this file, applied:
    // a port in the ephemeral range may only claim a flow together with a
    // content guard. These have no framing to check, so there is no guard to
    // write — reinstate them if the real port assignments or a recognisable
    // header turn up. An unlabelled flow beats a wrongly labelled one.
    (64738, mumble::dissect_mumble),
];

/// UDP service ports, sorted by port number. See [`TCP_PORTS`].
static UDP_PORTS: &[(u16, PortDissector)] = &[
    // The UDP variants are the reflectors: a spoofed datagram to any of these
    // returns traffic to whoever the source address claimed to be. TCPMUX is
    // absent because it is a TCP service by definition (RFC 1078).
    (67, dhcp::dissect_dhcp),
    (68, dhcp::dissect_dhcp),
    (88, kerberos::dissect_kerberos),
    (111, rpc::dissect_rpc),
    (123, ntp::dissect_ntp),
    (137, nbns::dissect_nbns),
    (138, nbds::dissect_nbds),
    (161, snmp::dissect_snmp),
    (162, snmp::dissect_snmp),
    (319, ptp::dissect_ptp_udp),
    (320, ptp::dissect_ptp_udp),
    (464, kpasswd::dissect_kpasswd),
    (500, isakmp::dissect_isakmp),
    (513, rwho::dissect_rwho),
    (514, syslog::dissect_syslog),
    (520, rip::dissect_rip),
    // RIPng shares almost nothing with RIPv2 but its shape, so it gets its own
    // dissector rather than a version branch inside RIP's.
    (521, ripng::dissect_ripng),
    (546, dhcpv6::dissect_dhcpv6),
    (547, dhcpv6::dissect_dhcpv6),
    (1434, mssqlbrowser::dissect_mssqlbrowser),
    (1645, radius::dissect_radius),
    (1646, radius::dissect_radius),
    (1701, l2tp::dissect_l2tp),
    (1719, h225ras::dissect_h225ras),
    (1812, radius::dissect_radius),
    (1813, radius::dissect_radius),
    (1883, mqttsn::dissect_mqttsn),
    (1985, hsrp::dissect_hsrp),
    (2048, wccp::dissect_wccp),
    (2049, rpc::dissect_rpc),
    (2055, netflow::dissect_netflow),
    (2123, gtp::dissect_gtp),
    (2152, gtp::dissect_gtp),
    (2157, nsip::dissect_nsip),
    (2222, enip::dissect_enip),
    (2224, cip_safety::dissect_cip_safety),
    (2268, amt::dissect_amt),
    (3074, xbox_live_sdv2::dissect_xbox_live_sdv2),
    (3205, isns::dissect_isns),
    (3222, glbp::dissect_glbp),
    (3386, gtpprime::dissect_gtpprime),
    (3478, stun::dissect_stun),
    (3702, wsd::dissect_wsd),
    (3784, bfd::dissect_bfd),
    (3956, gvcp::dissect_gvcp),
    (4341, lisp::dissect_lisp),
    (4500, ipsec::dissect_nat_traversal),
    (4569, iax2::dissect_iax2),
    (4739, netflow::dissect_netflow),
    (4790, vxlangpe::dissect_vxlangpe),
    // OPC UA PubSub (UADP) shares UDP 4840 with OPC UA TCP on the same port,
    // but the UDP variant is the publish/subscribe model (IEC 62541-14).
    (4840, uadp::dissect_uadp),
    (5004, rtpmidi::dissect_rtpmidi),
    (5005, rtpmidi::dissect_rtpmidi),
    (5060, sip::dissect_sip),
    (5061, sip::dissect_sip),
    (5100, p_net::dissect_p_net),
    (5246, capwap::dissect_capwap),
    (5247, capwap::dissect_capwap),
    (5351, pcp::dissect_pcp),
    (5500, mechatrolink::dissect_mechatrolink),
    (5540, matter::dissect_matter),
    (5554, ccp::dissect_ccp),
    (5555, xcp::dissect_xcp),
    (5568, dmx::dissect_sacn),
    (5683, coap::dissect_coap),
    (6081, geneve::dissect_geneve),
    (6343, sflow::dissect_sflow),
    (6454, dmx::dissect_artnet),
    (6771, bfd::dissect_bfd),
    // Each AFS service has its own port in this block, and the port is what
    // names the server a packet belongs to.
    (8805, pfcp::dissect_pfcp),
    (9302, psn_matchmaking_v3::dissect_psn_matchmaking_v3),
    (9303, psn_matchmaking_v3::dissect_psn_matchmaking_v3),
    (9600, omron_fins_udp_detail::dissect_omron_fins_udp_detail),
    (9995, netflow::dissect_netflow),
    (12201, gelf::dissect_gelf),
    (13400, doip::dissect_doip),
    (20000, dnp3::dissect_dnp3),
    (27018, epic_online_eos_p2p::dissect_epic_online_eos_p2p),
    (27019, epic_online_eos_p2p::dissect_epic_online_eos_p2p),
    (27036, steam_datagram_relay::dissect_steam_datagram_relay),
    (30211, nintendo_npln_p2p::dissect_nintendo_npln_p2p),
    (44818, enip::dissect_enip),
    (47808, bacnet::dissect_bacnet),
    (
        48898,
        beckhoff_twincat_analytics::dissect_beckhoff_twincat_analytics,
    ),
    (51820, wireguard::dissect_wireguard),
];

/// Every port either table claims. Used by the robustness sweep to fuzz each
/// dispatched port with malformed payloads.
#[cfg(test)]
pub(crate) fn all_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = TCP_PORTS
        .iter()
        .chain(UDP_PORTS.iter())
        .map(|(p, _)| *p)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binary search is only correct on a sorted table, and a duplicated port
    /// would mean one of the two dissectors is silently unreachable.
    #[test]
    fn tables_are_sorted_and_unique() {
        for (name, table) in [("TCP", TCP_PORTS), ("UDP", UDP_PORTS)] {
            for pair in table.windows(2) {
                assert!(
                    pair[0].0 < pair[1].0,
                    "{name}_PORTS is unsorted or has a duplicate at port {}",
                    pair[0].0
                );
            }
        }
        for pair in SCTP_PPIDS.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "SCTP_PPIDS is unsorted or has a duplicate at PPID {}",
                pair[0].0
            );
        }
    }

    #[test]
    fn sctp_ppids_resolve() {
        assert!(sctp_ppid(60).is_some(), "PPID 60 is NGAP");
        assert!(sctp_ppid(18).is_some(), "PPID 18 is S1AP");
        assert!(sctp_ppid(0).is_none(), "PPID 0 is unspecified");
    }

    #[test]
    fn well_known_ports_resolve() {
        assert!(tcp(51234, 443).is_some(), "TCP 443 should bind");
        assert!(
            tcp(443, 51234).is_some(),
            "TCP 443 should bind as source too"
        );
        assert!(udp(51234, 161).is_some(), "UDP 161 should bind");
        assert!(tcp(51234, 51235).is_none(), "ephemeral pairs bind nothing");
    }

    /// The destination port wins when both sides happen to name a service.
    #[test]
    fn destination_port_takes_precedence() {
        let by_dst = tcp(3306, 443).expect("443 binds");
        let direct = lookup(TCP_PORTS, 443).expect("443 binds");
        assert!(std::ptr::fn_addr_eq(by_dst, direct));
    }
}
