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
    ads, aerospike, afp, amqp, amt, aodv, aprs, babel, bacnet, beanstalk, beats, bfcp, bfd, bgp,
    bitcoin, bmp, bolt, capwap, cassandra, cclink_ie_field_basic, ceph, clamav, cldap, clickhouse,
    cmp, cnip, coap, coap_tcp, collectd, dcerpc, dhcp, dhcpfo, dhcpv6, diameter, dicom, dlms, dlsw,
    dmx, dnp3, dns_tcp, doip, e1ap, edonkey, elasticsearch, enip, f1ap, fcip, ff_hse, finger, fins,
    firebird, fluentd, fox, ftp, ganglia, gearman, gelf, geneve, git, glbp, gnutella, gopher,
    graphite, gtp, gtpprime, gvcp, h225ras, hadooprpc, hartip, hl7, hnbap, hsms, hsrp, iax2, ibmmq,
    ica, ident, iec104, imap, influxdb, ipp, ipsec, irc, isakmp, iscsi, isns, jaeger, kafka,
    kerberos, knxip, kpasswd, l2tp, lcsap, ldap, ldp, lisp, lpd, lustre, lwapp, m2ap, m2pa, m2ua,
    m3ap, m3ua, managesieve, matter, megaco, memcached, mgcp, minecraft, mle, modbus, mongodb,
    mqtt, mqttsn, msdp, msrp, mssqlbrowser, mumble, mysql, nats, nbap, nbd, nbds, nbns, ndmp,
    nebula, netflow, ngap, ninep, nntp, nrpe, nsip, nsq, ntp, nvmeof, olsr, opcua, openflow,
    opensafety, openwire, ovsdb, pcep, pcoip, pcp, pfcp, pop3, postgres, pptp, ptp, pulsar, q931,
    radius, radmin, rdp, redis, relp, rethinkdb, rexec, rfb, riak, rip, ripng, rlogin, rmcp,
    roughtime, rpc, rpkirtr, rsh, rsync, rtmp, rtpmidi, rtsp, rua, rwho, rx, s1ap, sabp, sane,
    sap_announce, sbcap, sflow, sip, skinny, slmp, slp, small_services, smb, smpp, smtp, snmp,
    socks, spamd, srtp_ge, ssdp, ssh, statsd, stomp, stun, sua, svn, syslog, tacacs, tds, telnet,
    teredo, tftp, tls, tns, twamp, uadp, vxlangpe, wccp, whois, wireguard, wsd, xcp, xdmcp, xmpp,
    xnap, zabbix, zerotier, zookeeper,
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
    (7, megaco::dissect_megaco),
    (18, s1ap::dissect_s1ap),
    (19, rua::dissect_rua),
    (20, hnbap::dissect_hnbap),
    (24, sbcap::dissect_sbcap),
    (25, nbap::dissect_nbap),
    (29, lcsap::dissect_lcsap),
    (31, sabp::dissect_sabp),
    (43, m2ap::dissect_m2ap),
    (44, m3ap::dissect_m3ap),
    (46, diameter::dissect_diameter),
    (47, diameter::dissect_diameter),
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
    (1, small_services::dissect_tcpmux),
    (7, small_services::dissect_echo),
    (9, small_services::dissect_discard),
    (13, small_services::dissect_daytime),
    (17, small_services::dissect_qotd),
    (19, small_services::dissect_chargen),
    (21, ftp::dissect_ftp),
    (22, ssh::dissect_ssh),
    (23, telnet::dissect_telnet),
    (25, smtp::dissect_smtp),
    (43, whois::dissect_whois),
    (49, tacacs::dissect_tacacs),
    (53, dns_tcp::dissect_dns_tcp),
    (70, gopher::dissect_gopher),
    (79, finger::dissect_finger),
    (88, kerberos::dissect_kerberos),
    (104, dicom::dissect_dicom),
    (110, pop3::dissect_pop3),
    (111, rpc::dissect_rpc),
    (113, ident::dissect_ident),
    (119, nntp::dissect_nntp),
    (135, dcerpc::dissect_dcerpc),
    (139, smb::dissect_smb),
    (143, imap::dissect_imap),
    (179, bgp::dissect_bgp),
    (323, rpkirtr::dissect_rpkirtr),
    (389, ldap::dissect_ldap),
    (427, slp::dissect_slp),
    (443, tls::dissect_tls),
    (445, smb::dissect_smb),
    (464, kpasswd::dissect_kpasswd),
    (502, modbus::dissect_modbus),
    (512, rexec::dissect_rexec),
    (513, rlogin::dissect_rlogin),
    (514, rsh::dissect_rsh),
    (515, lpd::dissect_lpd),
    (548, afp::dissect_afp),
    (554, rtsp::dissect_rtsp),
    (564, ninep::dissect_9p),
    (587, smtp::dissect_smtp),
    (601, syslog::dissect_syslog),
    (631, ipp::dissect_ipp),
    (639, msdp::dissect_msdp),
    (646, ldp::dissect_ldp),
    (647, dhcpfo::dissect_dhcpfo),
    (783, spamd::dissect_spamd),
    (829, cmp::dissect_cmp),
    (861, twamp::dissect_twamp),
    (862, twamp::dissect_twamp),
    (873, rsync::dissect_rsync),
    (988, lustre::dissect_lustre),
    (1080, socks::dissect_socks),
    (1089, ff_hse::dissect_ff_hse),
    (1090, ff_hse::dissect_ff_hse),
    (1091, ff_hse::dissect_ff_hse),
    (1414, ibmmq::dissect_ibmmq),
    (1433, tds::dissect_tds),
    (1494, ica::dissect_ica),
    (1521, tns::dissect_tns),
    (1720, q931::dissect_q931),
    (1723, pptp::dissect_pptp),
    (1883, mqtt::dissect_mqtt),
    (1911, fox::dissect_fox),
    (1935, rtmp::dissect_rtmp),
    (2000, skinny::dissect_skinny),
    (2003, graphite::dissect_graphite),
    (2049, rpc::dissect_rpc),
    (2065, dlsw::dissect_dlsw),
    (2181, zookeeper::dissect_zookeeper),
    (2404, iec104::dissect_iec104),
    (2514, relp::dissect_relp),
    (2575, hl7::dissect_hl7),
    (2775, smpp::dissect_smpp),
    (2855, msrp::dissect_msrp),
    (2944, megaco::dissect_megaco),
    (2945, megaco::dissect_megaco),
    (3000, aerospike::dissect_aerospike),
    (3050, firebird::dissect_firebird),
    // iSNS sits just below iSCSI's own port, and is where an initiator's
    // targets come from in the first place.
    (3205, isns::dissect_isns),
    (3225, fcip::dissect_fcip),
    (3238, bfcp::dissect_bfcp),
    (3260, iscsi::dissect_iscsi),
    (3306, mysql::dissect_mysql),
    (3310, clamav::dissect_clamav),
    (3389, rdp::dissect_rdp),
    (3690, svn::dissect_svn),
    (3868, diameter::dissect_diameter),
    (4059, dlms::dissect_dlms),
    (4150, nsq::dissect_nsq),
    (4172, pcoip::dissect_pcoip),
    (4189, pcep::dissect_pcep),
    (4190, managesieve::dissect_managesieve),
    (4222, nats::dissect_nats),
    (4420, nvmeof::dissect_nvmeof),
    (4662, edonkey::dissect_edonkey),
    (4730, gearman::dissect_gearman),
    (4840, opcua::dissect_opcua),
    (4899, radmin::dissect_radmin),
    (5000, hsms::dissect_hsms),
    (5007, slmp::dissect_slmp),
    (5044, beats::dissect_beats),
    (5222, xmpp::dissect_xmpp),
    (5269, xmpp::dissect_xmpp),
    (5432, postgres::dissect_postgres),
    (5666, nrpe::dissect_nrpe),
    (5672, amqp::dissect_amqp),
    (5683, coap_tcp::dissect_coap_tcp),
    (5684, coap_tcp::dissect_coap_tcp),
    (5900, rfb::dissect_rfb),
    (6346, gnutella::dissect_gnutella),
    (6379, redis::dissect_redis),
    (6514, syslog::dissect_syslog),
    (6566, sane::dissect_sane),
    (6640, ovsdb::dissect_ovsdb),
    (6641, ovsdb::dissect_ovsdb),
    (6642, ovsdb::dissect_ovsdb),
    (6650, pulsar::dissect_pulsar),
    (6653, openflow::dissect_openflow),
    (6667, irc::dissect_irc),
    (6697, irc::dissect_irc),
    (6789, ceph::dissect_ceph),
    (7687, bolt::dissect_bolt),
    (8020, hadooprpc::dissect_hadooprpc),
    (8087, riak::dissect_riak),
    (8333, bitcoin::dissect_bitcoin),
    (9000, clickhouse::dissect_clickhouse),
    (9042, cassandra::dissect_cassandra),
    (9092, kafka::dissect_kafka),
    (9300, elasticsearch::dissect_elasticsearch),
    (9418, git::dissect_git),
    (9600, fins::dissect_fins),
    (10000, ndmp::dissect_ndmp),
    (10050, zabbix::dissect_zabbix),
    (10051, zabbix::dissect_zabbix),
    (10809, nbd::dissect_nbd),
    (11019, bmp::dissect_bmp),
    (11112, dicom::dissect_dicom),
    (11211, memcached::dissect_memcached),
    (11300, beanstalk::dissect_beanstalk),
    (13400, doip::dissect_doip),
    (14580, aprs::dissect_aprs),
    (18245, srtp_ge::dissect_srtp_ge),
    (18333, bitcoin::dissect_bitcoin),
    (20000, dnp3::dissect_dnp3),
    (24007, rpc::dissect_rpc),
    (24224, fluentd::dissect_fluentd),
    (25565, minecraft::dissect_minecraft),
    (27017, mongodb::dissect_mongodb),
    (28015, rethinkdb::dissect_rethinkdb),
    (38333, bitcoin::dissect_bitcoin),
    (44818, enip::dissect_enip),
    (48898, ads::dissect_ads),
    (61613, stomp::dissect_stomp),
    (61616, openwire::dissect_openwire),
    (64738, mumble::dissect_mumble),
];

/// UDP service ports, sorted by port number. See [`TCP_PORTS`].
static UDP_PORTS: &[(u16, PortDissector)] = &[
    // The UDP variants are the reflectors: a spoofed datagram to any of these
    // returns traffic to whoever the source address claimed to be. TCPMUX is
    // absent because it is a TCP service by definition (RFC 1078).
    (7, small_services::dissect_echo),
    (9, small_services::dissect_discard),
    (13, small_services::dissect_daytime),
    (17, small_services::dissect_qotd),
    (19, small_services::dissect_chargen),
    (37, small_services::dissect_time),
    (67, dhcp::dissect_dhcp),
    (68, dhcp::dissect_dhcp),
    (69, tftp::dissect_tftp),
    (88, kerberos::dissect_kerberos),
    (111, rpc::dissect_rpc),
    (123, ntp::dissect_ntp),
    (137, nbns::dissect_nbns),
    (138, nbds::dissect_nbds),
    (161, snmp::dissect_snmp),
    (162, snmp::dissect_snmp),
    (177, xdmcp::dissect_xdmcp),
    (319, ptp::dissect_ptp_udp),
    (320, ptp::dissect_ptp_udp),
    (389, cldap::dissect_cldap),
    (427, slp::dissect_slp),
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
    (623, rmcp::dissect_rmcp),
    (654, aodv::dissect_aodv),
    (698, olsr::dissect_olsr),
    (1089, ff_hse::dissect_ff_hse),
    (1090, ff_hse::dissect_ff_hse),
    (1091, ff_hse::dissect_ff_hse),
    (1434, mssqlbrowser::dissect_mssqlbrowser),
    (1628, cnip::dissect_cnip),
    (1629, cnip::dissect_cnip),
    (1645, radius::dissect_radius),
    (1646, radius::dissect_radius),
    (1701, l2tp::dissect_l2tp),
    (1719, h225ras::dissect_h225ras),
    (1812, radius::dissect_radius),
    (1813, radius::dissect_radius),
    (1883, mqttsn::dissect_mqttsn),
    (1900, ssdp::dissect_ssdp),
    (1985, hsrp::dissect_hsrp),
    (2002, roughtime::dissect_roughtime),
    (2048, wccp::dissect_wccp),
    (2049, rpc::dissect_rpc),
    (2055, netflow::dissect_netflow),
    (2123, gtp::dissect_gtp),
    (2152, gtp::dissect_gtp),
    (2157, nsip::dissect_nsip),
    (2222, enip::dissect_enip),
    (2268, amt::dissect_amt),
    (2427, mgcp::dissect_mgcp),
    (2727, mgcp::dissect_mgcp),
    (2944, megaco::dissect_megaco),
    (2945, megaco::dissect_megaco),
    (3205, isns::dissect_isns),
    (3222, glbp::dissect_glbp),
    (3386, gtpprime::dissect_gtpprime),
    (3478, stun::dissect_stun),
    (3479, stun::dissect_stun),
    (3544, teredo::dissect_teredo),
    (3622, ff_hse::dissect_ff_hse),
    (3671, knxip::dissect_knxip),
    (3702, wsd::dissect_wsd),
    (3784, bfd::dissect_bfd),
    (3956, gvcp::dissect_gvcp),
    (4172, pcoip::dissect_pcoip),
    (4242, nebula::dissect_nebula),
    (4341, lisp::dissect_lisp),
    (4342, lisp::dissect_lisp),
    (4500, ipsec::dissect_nat_traversal),
    (4569, iax2::dissect_iax2),
    (4739, netflow::dissect_netflow),
    (4790, vxlangpe::dissect_vxlangpe),
    // OPC UA PubSub (UADP) shares UDP 4840 with OPC UA TCP on the same port,
    // but the UDP variant is the publish/subscribe model (IEC 62541-14).
    (4840, uadp::dissect_uadp),
    (5004, rtpmidi::dissect_rtpmidi),
    (5005, rtpmidi::dissect_rtpmidi),
    (5007, slmp::dissect_slmp),
    (5060, sip::dissect_sip),
    (5061, sip::dissect_sip),
    (5094, hartip::dissect_hartip),
    (5246, capwap::dissect_capwap),
    (5247, capwap::dissect_capwap),
    (5351, pcp::dissect_pcp),
    (5540, matter::dissect_matter),
    (5555, xcp::dissect_xcp),
    (5568, dmx::dissect_sacn),
    (5683, coap::dissect_coap),
    (6081, geneve::dissect_geneve),
    (6343, sflow::dissect_sflow),
    (6454, dmx::dissect_artnet),
    (6696, babel::dissect_babel),
    (6831, jaeger::dissect_jaeger),
    // Each AFS service has its own port in this block, and the port is what
    // names the server a packet belongs to.
    (7000, rx::dissect_rx),
    (7001, rx::dissect_rx),
    (7002, rx::dissect_rx),
    (7003, rx::dissect_rx),
    (7004, rx::dissect_rx),
    (7005, rx::dissect_rx),
    (7006, rx::dissect_rx),
    (7007, rx::dissect_rx),
    (7008, rx::dissect_rx),
    (7009, rx::dissect_rx),
    (8089, influxdb::dissect_influxdb),
    (8125, statsd::dissect_statsd),
    (8649, ganglia::dissect_ganglia),
    (8755, opensafety::dissect_opensafety),
    (8805, pfcp::dissect_pfcp),
    (9600, fins::dissect_fins),
    (9875, sap_announce::dissect_sap_announce),
    (9877, opensafety::dissect_opensafety),
    (9993, zerotier::dissect_zerotier),
    (9995, netflow::dissect_netflow),
    (12201, gelf::dissect_gelf),
    (12222, lwapp::dissect_lwapp),
    (12223, lwapp::dissect_lwapp),
    (13400, doip::dissect_doip),
    (19788, mle::dissect_mle),
    (20000, dnp3::dissect_dnp3),
    (25826, collectd::dissect_collectd),
    (44818, enip::dissect_enip),
    (47808, bacnet::dissect_bacnet),
    (51820, wireguard::dissect_wireguard),
    (61450, cclink_ie_field_basic::dissect_cclink_ie_field_basic),
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
