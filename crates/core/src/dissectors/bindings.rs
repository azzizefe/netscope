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
    bitcoin, bmp, bolt, bsap, capwap, cassandra, cclink_ie_field_basic, ccp, ceph, clamav, cldap, clickhouse,
    cmp, cnip, coap, coap_tcp, codesys, collectd, dcerpc, dhcp, dhcpfo, dhcpv6, diameter, dicom, dlms, dlsw,
    dmx, dnp3, dns_tcp, doip, e1ap, e2ap, edonkey, elasticsearch, enip, f1ap, fcip, ff_hse, finger, fins,
    firebird, fluentd, focas, fou, fox, ftp, ganglia, gearman, gelf, geneve, git, glbp, gnutella, gopher,
    graphite, gtp, gtpprime, gue, gvcp, h225ras, hadooprpc, hartip, hl7, hnbap, hsms, hsrp, iax2, ibmmq,
    ica, ident, iec104, imap, influxdb, ipp, ipsec, irc, isakmp, iscsi, isns, jaeger, kafka,
    kerberos, knxip, kpasswd, l2tp, lcsap, ldap, ldp, lisp, lpd, lustre, lwapp, m2ap, m2pa, m2ua,
    m3ap, m3ua, managesieve, matter, megaco, memcached, mgcp, minecraft, mle, modbus, mongodb, mpls_in_udp,
    mqtt, mqttsn, msdp, msrp, mssqlbrowser, mumble, mysql, nats, nbap, nbd, nbds, nbns, ndmp,
    nebula, netflow, ngap, ninep, nntp, nrpe, nrppa, nsip, nsq, ntp, nvmeof, olsr, opcua, openflow,
    opensafety, openr, openwire, oran_e1, ovsdb, pcep, pcoip, pcp, pfcp, pop3, postgres, pptp, ptp, pulsar, q931,
    radius, radmin, rdp, redis, relp, rethinkdb, rexec, rfb, riak, rip, ripng, rlogin, rmcp, roc_plus,
    roughtime, rpc, rpkirtr, rsh, rsync, rtmp, rtpmidi, rtsp, rua, rwho, rx, s1ap, sabp, sane,
    sap_announce, sbcap, sflow, sip, skinny, slmp, slp, small_services, smb, smpp, smtp, snmp,
    socks, spamd, srtp_ge, ssdp, ssh, statsd, stomp, stt, stun, sua, svn, syslog, tacacs, tds, telnet,
    teredo, tftp, tls, tns, toyopuc, tsp_timestamp, twamp, uadp, vnet_ip, vxlangpe, w1ap, wccp, whois, wireguard, wsd, x2ap, xcp, xdmcp, xmpp,
    xnap, xwap, zabbix, zerotier, zookeeper, beegfs, coda, edp, hdfs_data, moosefs, ncp, oftp, orangefs, perforce, sheepdog, syncthing, uucp,
    cwmp, dali, esphome, homekit, insteon, mtconnect, onvif, rist, semtech_lora, x10, zwave,
    tarantool, hbase, impala, vertica, teradata, saphana, informix, netezza, ingres, maxdb, voldemort,
    opentsdb, tdengine, questdb, orientdb, etcd, tikv, couchbase, couchdb, arangodb, trino, druid,
    prometheus_rw, victoriametrics,
    rabbitmq_stream, artemis_core, solace_smf, tibco_rv, tibco_ems, nanomsg_sp, otlp_grpc, otlp_http,
    zipkin, riemann, munin, sensu, netdata, splunk_s2s, loki_push, vector_native, graphite_pickle,
    icinga2, nagios_nsca, nagios_ndo, collectd_v5, ganglia_gmetad, zabbix_active, telegraf_influxv2,
    netconf, gnmi, upnp_soap, guacamole, nomachine_nx, mosh, wap_wsp_wtp,
    wbxml, dns_over_quic, matrix_federation, gemini_proto,
    epics_ca, epics_pva, slurm_rpc, pmix, tango_controls, gbt26982, of_config, ethercat_mailbox,
    opc_ua_pubsub, cip_motion, cip_safety, gbt_20414, gbt_19582, fiveg_n4, mpi_wire, ucx_hpc, safetynet_p, hart_wireless, isa100_11a,
    dvb_ait, dvb_bat, dvb_data_mpe, dvb_eit, dvb_ipdc, dvb_nit, dvb_s2_bb, dvb_s2_table, dvb_sdt, dvb_sit, dvb_tdt, dvb_tot, dvbci, etsi_card_app_toolkit, mp2t, mp4ves, mpeg_audio, mpeg_ca, mpeg_descriptor, mpeg_dsmcc, mpeg_pat, mpeg_pes, mpeg_pmt, mpeg_sect, mpeg1, scte35,
    h1, h221_nonstd, h223, h224, h225, h235, h245, h248, h248_10, h248_2, h248_3gpp, h248_7, h248_annex_c, h248_annex_e, h248_q1950, h261, h263, h263p, h264, h265, h282, h283, h323, h450, h450_ros, h460, h501,,
    dcerpc_atsvc, dcerpc_bossvr, dcerpc_browser, dcerpc_budb, dcerpc_butc, dcerpc_cds_clerkserver, dcerpc_cds_solicit, dcerpc_clusapi, dcerpc_conv, dcerpc_cprpc_server, dcerpc_dce122, dcerpc_dfs, dcerpc_dnsserver, dcerpc_drsuapi, dcerpc_dssetup, dcerpc_dtsprovider, dcerpc_dtsstime_req, dcerpc_efs, dcerpc_epm, dcerpc_eventlog, dcerpc_fileexp, dcerpc_fldb, dcerpc_frsapi, dcerpc_frsrpc, dcerpc_frstrans, dcerpc_fsrvp, dcerpc_ftserver, dcerpc_icl_rpc, dcerpc_initshutdown, dcerpc_iwbemlevel1login, dcerpc_iwbemloginclientid, dcerpc_iwbemloginclientidex, dcerpc_iwbemservices, dcerpc_krb5rpc, dcerpc_llb, dcerpc_lsa, dcerpc_mapi, dcerpc_mdssvc, dcerpc_messenger, dcerpc_mgmt, dcerpc_misc, dcerpc_ndr, dcerpc_netlogon, dcerpc_nspi, dcerpc_nt, dcerpc_pnp, dcerpc_rcg, dcerpc_rdaclif, dcerpc_rdpdr_smartcard, dcerpc_rep_proc, dcerpc_rfr, dcerpc_roverride, dcerpc_rpriv, dcerpc_rras, dcerpc_rs_acct, dcerpc_rs_attr, dcerpc_rs_attr_schema, dcerpc_rs_bind, dcerpc_rs_misc, dcerpc_rs_pgo, dcerpc_rs_plcy, dcerpc_rs_prop_acct, dcerpc_rs_prop_acl, dcerpc_rs_prop_attr, dcerpc_rs_prop_pgo, dcerpc_rs_prop_plcy, dcerpc_rs_pwd_mgmt, dcerpc_rs_repadm, dcerpc_rs_replist, dcerpc_rs_repmgr, dcerpc_rs_unix, dcerpc_rsec_login, dcerpc_samr, dcerpc_secidmap, dcerpc_spoolss, dcerpc_srvsvc, dcerpc_svcctl, dcerpc_tapi, dcerpc_taskschedulerservice, dcerpc_tkn4int, dcerpc_trksvr, dcerpc_ubikdisk, dcerpc_ubikvote, dcerpc_update, dcerpc_winreg, dcerpc_winspool, dcerpc_witness, dcerpc_wkssvc, dcerpc_wzcsvc, dcom, dcom_dispatch, dcom_oxid, dcom_provideclassinfo, dcom_remact, dcom_remunkn, dcom_sysact, dcom_typeinfo,
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
    (27, x2ap::dissect_x2ap),
    (29, lcsap::dissect_lcsap),
    (31, sabp::dissect_sabp),
    (43, m2ap::dissect_m2ap),
    (44, m3ap::dissect_m3ap),
    (46, diameter::dissect_diameter),
    (47, diameter::dissect_diameter),
    (59, xwap::dissect_xwap),
    (60, ngap::dissect_ngap),
    (61, xnap::dissect_xnap),
    (62, f1ap::dissect_f1ap),
    (63, w1ap::dissect_w1ap),
    (64, e1ap::dissect_e1ap),
    (66, nrppa::dissect_nrppa),
    (70, e2ap::dissect_e2ap),
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
    (11, small_services::dissect_systat),
    (13, small_services::dissect_daytime),
    (15, small_services::dissect_netstat),
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
    (503, gbt_19582::dissect_gbt_19582),
    (512, rexec::dissect_rexec),
    (513, rlogin::dissect_rlogin),
    (514, rsh::dissect_rsh),
    (515, lpd::dissect_lpd),
    (524, ncp::dissect_ncp),
    (540, uucp::dissect_uucp),
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
    (830, netconf::dissect_netconf),
    (861, twamp::dissect_twamp),
    (862, twamp::dissect_twamp),
    (873, rsync::dissect_rsync),
    (988, lustre::dissect_lustre),
    (1025, teradata::dissect_teradata),
    (1080, socks::dissect_socks),
    (1089, ff_hse::dissect_ff_hse),
    (1090, ff_hse::dissect_ff_hse),
    (1091, ff_hse::dissect_ff_hse),
    (1234, bsap::dissect_bsap),
    (1414, ibmmq::dissect_ibmmq),
    (1433, tds::dissect_tds),
    (1494, ica::dissect_ica),
    (1521, tns::dissect_tns),
    (1526, informix::dissect_informix),
    (1666, perforce::dissect_perforce),
    (1720, q931::dissect_q931),
    (1723, pptp::dissect_pptp),
    (1783, ingres::dissect_ingres),
    (1883, mqtt::dissect_mqtt),
    (1911, fox::dissect_fox),
    (1935, rtmp::dissect_rtmp),
    (1965, gemini_proto::dissect_gemini_proto),
    (2000, skinny::dissect_skinny),
    (2003, graphite::dissect_graphite),
    (2004, graphite_pickle::dissect_graphite_pickle),
    (2049, rpc::dissect_rpc),
    (2065, dlsw::dissect_dlsw),
    (2181, zookeeper::dissect_zookeeper),
    (2379, etcd::dissect_etcd),
    (2404, iec104::dissect_iec104),
    (2424, orientdb::dissect_orientdb),
    (2514, relp::dissect_relp),
    (2575, hl7::dissect_hl7),
    (2775, smpp::dissect_smpp),
    (2855, msrp::dissect_msrp),
    (2944, megaco::dissect_megaco),
    (2945, megaco::dissect_megaco),
    (3000, aerospike::dissect_aerospike),
    (3031, sensu::dissect_sensu),
    (3050, firebird::dissect_firebird),
    (3100, loki_push::dissect_loki_push),
    // iSNS sits just below iSCSI's own port, and is where an initiator's
    // targets come from in the first place.
    (3205, isns::dissect_isns),
    (3225, fcip::dissect_fcip),
    (3238, bfcp::dissect_bfcp),
    (3260, iscsi::dissect_iscsi),
    (3301, tarantool::dissect_tarantool),
    (3305, oftp::dissect_oftp),
    (3306, mysql::dissect_mysql),
    (3310, clamav::dissect_clamav),
    (3334, orangefs::dissect_orangefs),
    (3389, rdp::dissect_rdp),
    (3690, svn::dissect_svn),
    (3868, diameter::dissect_diameter),
    (4000, nomachine_nx::dissect_nomachine_nx),
    (4059, dlms::dissect_dlms),
    (4096, toyopuc::dissect_toyopuc),
    (4150, nsq::dissect_nsq),
    (4172, pcoip::dissect_pcoip),
    (4189, pcep::dissect_pcep),
    (4190, managesieve::dissect_managesieve),
    (4222, nats::dissect_nats),
    (4242, opentsdb::dissect_opentsdb),
    (4317, otlp_grpc::dissect_otlp_grpc),
    (4318, otlp_http::dissect_otlp_http),
    (4420, nvmeof::dissect_nvmeof),
    (4662, edonkey::dissect_edonkey),
    (4730, gearman::dissect_gearman),
    (4822, guacamole::dissect_guacamole),
    (4840, opcua::dissect_opcua),
    (4899, radmin::dissect_radmin),
    (4949, munin::dissect_munin),
    (5000, hsms::dissect_hsms),
    (5001, mtconnect::dissect_mtconnect),
    (5007, slmp::dissect_slmp),
    (5044, beats::dissect_beats),
    (5064, epics_ca::dissect_epics_ca),
    (5065, epics_ca::dissect_epics_ca),
    (5075, epics_pva::dissect_epics_pva),
    (5222, xmpp::dissect_xmpp),
    (5269, xmpp::dissect_xmpp),
    (5432, postgres::dissect_postgres),
    (5433, vertica::dissect_vertica),
    (5480, netezza::dissect_netezza),
    (5552, rabbitmq_stream::dissect_rabbitmq_stream),
    (5554, nanomsg_sp::dissect_nanomsg_sp),
    (5555, riemann::dissect_riemann),
    (5665, icinga2::dissect_icinga2),
    (5666, nrpe::dissect_nrpe),
    (5667, nagios_nsca::dissect_nagios_nsca),
    (5668, nagios_ndo::dissect_nagios_ndo),
    (5672, amqp::dissect_amqp),
    (5683, coap_tcp::dissect_coap_tcp),
    (5684, coap_tcp::dissect_coap_tcp),
    (5900, rfb::dissect_rfb),
    (5984, couchdb::dissect_couchdb),
    (6000, vector_native::dissect_vector_native),
    (6030, tdengine::dissect_tdengine),
    (6053, esphome::dissect_esphome),
    (6120, pmix::dissect_pmix),
    (6346, gnutella::dissect_gnutella),
    (6379, redis::dissect_redis),
    (6500, mpi_wire::dissect_mpi_wire),
    (6514, syslog::dissect_syslog),
    (6566, sane::dissect_sane),
    (6619, oftp::dissect_oftp),
    (6640, ovsdb::dissect_ovsdb),
    (6641, ovsdb::dissect_ovsdb),
    (6642, ovsdb::dissect_ovsdb),
    (6650, pulsar::dissect_pulsar),
    (6653, openflow::dissect_openflow),
    (6654, of_config::dissect_of_config),
    (6666, voldemort::dissect_voldemort),
    (6667, irc::dissect_irc),
    (6697, irc::dissect_irc),
    (6789, ceph::dissect_ceph),
    (6817, slurm_rpc::dissect_slurm_rpc),
    (6818, slurm_rpc::dissect_slurm_rpc),
    (7000, sheepdog::dissect_sheepdog),
    (7210, maxdb::dissect_maxdb),
    (7222, tibco_ems::dissect_tibco_ems),
    (7269, maxdb::dissect_maxdb),
    (7547, cwmp::dissect_cwmp),
    (7687, bolt::dissect_bolt),
    (8000, onvif::dissect_onvif),
    (8003, beegfs::dissect_beegfs),
    (8020, hadooprpc::dissect_hadooprpc),
    (8082, druid::dissect_druid),
    (8086, telegraf_influxv2::dissect_telegraf_influxv2),
    (8087, riak::dissect_riak),
    (8193, focas::dissect_focas),
    (8333, bitcoin::dissect_bitcoin),
    (8428, victoriametrics::dissect_victoriametrics),
    (8443, trino::dissect_trino),
    (8448, matrix_federation::dissect_matrix_federation),
    (8529, arangodb::dissect_arangodb),
    (8651, ganglia_gmetad::dissect_ganglia_gmetad),
    (8888, druid::dissect_druid),
    (9000, clickhouse::dissect_clickhouse),
    (9009, questdb::dissect_questdb),
    (9042, cassandra::dissect_cassandra),
    (9088, informix::dissect_informix),
    (9090, prometheus_rw::dissect_prometheus_rw),
    (9092, kafka::dissect_kafka),
    (9300, elasticsearch::dissect_elasticsearch),
    (9339, gnmi::dissect_gnmi),
    (9411, zipkin::dissect_zipkin),
    (9418, git::dissect_git),
    (9419, moosefs::dissect_moosefs),
    (9600, fins::dissect_fins),
    (9761, insteon::dissect_insteon),
    (9997, splunk_s2s::dissect_splunk_s2s),
    (10000, tango_controls::dissect_tango_controls),
    (10001, ndmp::dissect_ndmp),
    (10050, zabbix::dissect_zabbix),
    (10051, zabbix_active::dissect_zabbix_active),
    (10809, nbd::dissect_nbd),
    (11019, bmp::dissect_bmp),
    (11112, dicom::dissect_dicom),
    (11210, couchbase::dissect_couchbase),
    (11211, memcached::dissect_memcached),
    (11300, beanstalk::dissect_beanstalk),
    (11740, codesys::dissect_codesys),
    (13337, ucx_hpc::dissect_ucx_hpc),
    (13400, doip::dissect_doip),
    (14580, aprs::dissect_aprs),
    (16000, hbase::dissect_hbase),
    (16020, hbase::dissect_hbase),
    (17830, ingres::dissect_ingres),
    (18245, srtp_ge::dissect_srtp_ge),
    (18333, bitcoin::dissect_bitcoin),
    (19999, netdata::dissect_netdata),
    (20000, gbt26982::dissect_gbt26982),
    (20001, dnp3::dissect_dnp3),
    (20002, gbt_20414::dissect_gbt_20414),
    (20160, tikv::dissect_tikv),
    (21000, impala::dissect_impala),
    (21050, impala::dissect_impala),
    (21071, ingres::dissect_ingres),
    (22000, syncthing::dissect_syncthing),
    (24007, rpc::dissect_rpc),
    (24224, fluentd::dissect_fluentd),
    (25565, minecraft::dissect_minecraft),
    (27017, mongodb::dissect_mongodb),
    (28015, rethinkdb::dissect_rethinkdb),
    (30015, saphana::dissect_saphana),
    (38333, bitcoin::dissect_bitcoin),
    (41230, zwave::dissect_zwave),
    (44818, enip::dissect_enip),
    (48898, ads::dissect_ads),
    (49152, upnp_soap::dissect_upnp_soap),
    (50010, hdfs_data::dissect_hdfs_data),
    (51827, homekit::dissect_homekit),
    (55555, solace_smf::dissect_solace_smf),
    (57400, gnmi::dissect_gnmi),
    (61613, stomp::dissect_stomp),
    (61616, openwire::dissect_openwire),
    (61617, artemis_core::dissect_artemis_core),
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
    (318, tsp_timestamp::dissect_tsp_timestamp),
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
    (524, ncp::dissect_ncp),
    (546, dhcpv6::dissect_dhcpv6),
    (547, dhcpv6::dissect_dhcpv6),
    (623, rmcp::dissect_rmcp),
    (654, aodv::dissect_aodv),
    (698, olsr::dissect_olsr),
    (853, dns_over_quic::dissect_dns_over_quic),
    (1089, ff_hse::dissect_ff_hse),
    (1090, ff_hse::dissect_ff_hse),
    (1091, ff_hse::dissect_ff_hse),
    (1234, bsap::dissect_bsap),
    (1434, mssqlbrowser::dissect_mssqlbrowser),
    (1628, cnip::dissect_cnip),
    (1629, cnip::dissect_cnip),
    (1645, radius::dissect_radius),
    (1646, radius::dissect_radius),
    (1680, semtech_lora::dissect_semtech_lora),
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
    (2223, cip_motion::dissect_cip_motion),
    (2224, cip_safety::dissect_cip_safety),
    (2268, amt::dissect_amt),
    (2427, mgcp::dissect_mgcp),
    (2430, coda::dissect_coda),
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
    (4000, roc_plus::dissect_roc_plus),
    (4096, toyopuc::dissect_toyopuc),
    (4172, pcoip::dissect_pcoip),
    (4242, nebula::dissect_nebula),
    (4268, bsap::dissect_bsap),
    (4341, lisp::dissect_lisp),
    (4342, lisp::dissect_lisp),
    (4500, ipsec::dissect_nat_traversal),
    (4569, iax2::dissect_iax2),
    (4739, netflow::dissect_netflow),
    (4790, vxlangpe::dissect_vxlangpe),
    (4803, dali::dissect_dali),
    // OPC UA PubSub (UADP) shares UDP 4840 with OPC UA TCP on the same port,
    // but the UDP variant is the publish/subscribe model (IEC 62541-14).
    (4840, uadp::dissect_uadp),
    (4841, opc_ua_pubsub::dissect_opc_ua_pubsub),
    (5004, rtpmidi::dissect_rtpmidi),
    (5005, rtpmidi::dissect_rtpmidi),
    (5007, slmp::dissect_slmp),
    (5060, sip::dissect_sip),
    (5061, sip::dissect_sip),
    (5064, epics_ca::dissect_epics_ca),
    (5065, epics_ca::dissect_epics_ca),
    (5075, epics_pva::dissect_epics_pva),
    (5094, hartip::dissect_hartip),
    (5095, hart_wireless::dissect_hart_wireless),
    (5246, capwap::dissect_capwap),
    (5247, capwap::dissect_capwap),
    (5351, pcp::dissect_pcp),
    (5540, matter::dissect_matter),
    (5554, ccp::dissect_ccp),
    (5555, xcp::dissect_xcp),
    (5556, fou::dissect_fou),
    (5568, dmx::dissect_sacn),
    (5683, coap::dissect_coap),
    (6080, gue::dissect_gue),
    (6081, geneve::dissect_geneve),
    (6112, edp::dissect_edp),
    (6343, sflow::dissect_sflow),
    (6454, dmx::dissect_artnet),
    (6635, mpls_in_udp::dissect_mpls_in_udp),
    (6683, openr::dissect_openr),
    (6696, babel::dissect_babel),
    (6771, bfd::dissect_bfd),
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
    (7471, stt::dissect_stt),
    (7500, tibco_rv::dissect_tibco_rv),
    (8003, beegfs::dissect_beegfs),
    (8089, influxdb::dissect_influxdb),
    (8125, statsd::dissect_statsd),
    (8649, ganglia::dissect_ganglia),
    (8755, opensafety::dissect_opensafety),
    (8805, pfcp::dissect_pfcp),
    (8806, fiveg_n4::dissect_fiveg_n4),
    (9009, questdb::dissect_questdb),
    (9200, wbxml::dissect_wbxml),
    (9201, wap_wsp_wtp::dissect_wap_wsp_wtp),
    (9600, fins::dissect_fins),
    (9761, insteon::dissect_insteon),
    (9875, sap_announce::dissect_sap_announce),
    (9877, opensafety::dissect_opensafety),
    (9993, zerotier::dissect_zerotier),
    (9995, netflow::dissect_netflow),
    (10000, x10::dissect_x10),
    (11740, codesys::dissect_codesys_discovery),
    (12201, gelf::dissect_gelf),
    (12222, lwapp::dissect_lwapp),
    (12223, lwapp::dissect_lwapp),
    (13000, vnet_ip::dissect_vnet_ip),
    (13001, vnet_ip::dissect_vnet_ip),
    (13002, vnet_ip::dissect_vnet_ip),
    (13400, doip::dissect_doip),
    (19788, mle::dissect_mle),
    (20000, dnp3::dissect_dnp3),
    (20001, rist::dissect_rist),
    (24130, isa100_11a::dissect_isa100_11a),
    (25826, collectd::dissect_collectd),
    (25827, collectd_v5::dissect_collectd_v5),
    (34980, ethercat_mailbox::dissect_ethercat_mailbox),
    (34981, safetynet_p::dissect_safetynet_p),
    (38463, oran_e1::dissect_oran_e1),
    (41230, zwave::dissect_zwave),
    (44818, enip::dissect_enip),
    (47808, bacnet::dissect_bacnet),
    (51820, wireguard::dissect_wireguard),
    (60001, mosh::dissect_mosh),
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
