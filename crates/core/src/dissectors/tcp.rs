// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::models::Protocol;

use super::{
    adsb, aerospike, afp, amqp, aprs, beanstalk, beats, bgp, bittorrent, bmp, bolt, cassandra,
    clamav, clickhouse, dcerpc, diameter, dicom, dnp3, doip, drda, edonkey, elasticsearch, enip,
    finger, firebird, fix, fluentd, ftp, gearman, git, gnutella, gopher, graphite, hadooprpc, hl7,
    http, http2, ica, ident, iec104, imap, ipp, irc, iscsi, kafka, kerberos, ldap, ldp, lpd,
    managesieve, megaco, memcached, minecraft, mms, modbus, mongodb, mqtt, msrp, mumble, mysql,
    mysqlx, nats, ndmp, nmea, nntp, nrpe, nsq, ntlm, opcua, openflow, openvpn, openwire, pcoip,
    pop3, postgres, pptp, pulsar, radmin, rdp, redis, relp, rethinkdb, rexec, rfb, riak, rlogin,
    rpc, rpkirtr, rsh, rsync, rtmp, rtsp, s7comm, sane, skinny, smb, smpp, smtp, socks, someip,
    spamd, spice, ssh, stomp, svn, tacacs, tds, telnet, tls, tns, websocket, whois, x11, xmpp,
    zabbix, zmtp, zookeeper, DissectedResult,
};

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct TcpFlowKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

struct TcpFlowStream {
    next_seq: u32,
    stream_data: Vec<u8>,
    buffered: BTreeMap<u32, Vec<u8>>,
    last_seen: Instant,
}

thread_local! {
    static REASSEMBLER: RefCell<HashMap<TcpFlowKey, TcpFlowStream>> = RefCell::new(HashMap::new());
}

#[cfg(test)]
pub fn clear_tcp_reassembler() {
    REASSEMBLER.with(|reasm_cell| {
        reasm_cell.borrow_mut().clear();
    });
}

pub fn dissect_tcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    #[cfg(test)]
    {
        super::tcp_analysis::clear_tcp_states();
    }

    let mut result = dissect_tcp_inner(src_ip, dst_ip, payload);
    if let Ok((tcp, rest)) = etherparse::TcpHeader::from_slice(payload) {
        let mut flags_byte = 0u8;
        if tcp.fin {
            flags_byte |= 0x01;
        }
        if tcp.syn {
            flags_byte |= 0x02;
        }
        if tcp.rst {
            flags_byte |= 0x04;
        }
        if tcp.psh {
            flags_byte |= 0x08;
        }
        if tcp.ack {
            flags_byte |= 0x10;
        }
        if tcp.urg {
            flags_byte |= 0x20;
        }
        if let Some(warning) =
            super::tcp_analysis::analyze_packet(super::tcp_analysis::TcpSegment {
                src_ip,
                dst_ip,
                src_port: tcp.source_port,
                dst_port: tcp.destination_port,
                seq: tcp.sequence_number,
                ack: tcp.acknowledgment_number,
                flags: flags_byte,
                win: tcp.window_size,
                payload_len: rest.len(),
            })
        {
            result.summary = format!("{warning} {}", result.summary);
        }

        if result.protocol == Protocol::Http {
            if let Some(dur) = super::srt::record_http(
                src_ip,
                dst_ip,
                tcp.source_port,
                tcp.destination_port,
                &result.summary,
            ) {
                result.summary = format!(
                    "{} [SRT: {:.1}ms]",
                    result.summary,
                    dur.as_secs_f64() * 1000.0
                );
            }
        }
    }
    result
}

fn dissect_tcp_inner(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let header = match etherparse::TcpHeader::from_slice(payload) {
        Ok((h, rest)) => (h, rest),
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: None,
                dst_port: None,
                protocol: Protocol::Unknown("malformed TCP".into()),
                summary: "Malformed TCP header".into(),
            };
        }
    };

    let (tcp, tcp_payload_raw) = header;
    let src_port = tcp.source_port;
    let dst_port = tcp.destination_port;

    let syn = tcp.syn;
    let ack = tcp.ack;
    let fin = tcp.fin;
    let rst = tcp.rst;

    let mut reassembled_payload = tcp_payload_raw.to_vec();

    if let (Some(sip), Some(dip)) = (src_ip, dst_ip) {
        if syn {
            let key = TcpFlowKey {
                src_ip: sip,
                src_port,
                dst_ip: dip,
                dst_port,
            };
            REASSEMBLER.with(|reasm_cell| {
                reasm_cell.borrow_mut().remove(&key);
            });
        } else if !tcp_payload_raw.is_empty() {
            let key = TcpFlowKey {
                src_ip: sip,
                src_port,
                dst_ip: dip,
                dst_port,
            };
            REASSEMBLER.with(|reasm_cell| {
                let mut reasm = reasm_cell.borrow_mut();
                let now = Instant::now();
                reasm.retain(|_, val| now.duration_since(val.last_seen) < Duration::from_secs(60));

                let stream = reasm.entry(key).or_insert_with(|| TcpFlowStream {
                    next_seq: tcp.sequence_number,
                    stream_data: Vec::new(),
                    buffered: BTreeMap::new(),
                    last_seen: now,
                });

                let seq = tcp.sequence_number;

                if seq == 0 && stream.next_seq > 0 {
                    stream.stream_data.clear();
                    stream.buffered.clear();
                    stream.next_seq = 0;
                }

                let mut is_contiguous = false;

                if seq == stream.next_seq || stream.stream_data.is_empty() {
                    if stream.stream_data.is_empty() {
                        stream.next_seq = seq;
                    }

                    let overlap = if seq < stream.next_seq {
                        (stream.next_seq - seq) as usize
                    } else {
                        0
                    };
                    if overlap < tcp_payload_raw.len() {
                        stream
                            .stream_data
                            .extend_from_slice(&tcp_payload_raw[overlap..]);
                        stream.next_seq = seq + tcp_payload_raw.len() as u32;
                        is_contiguous = true;
                    }

                    while let Some(next_data) = stream.buffered.remove(&stream.next_seq) {
                        stream.stream_data.extend_from_slice(&next_data);
                        stream.next_seq += next_data.len() as u32;
                        is_contiguous = true;
                    }
                } else if seq > stream.next_seq {
                    if stream.stream_data.len() + tcp_payload_raw.len() < 5 * 1024 * 1024 {
                        stream.buffered.insert(seq, tcp_payload_raw.to_vec());
                    }
                } else {
                    let overlap = (stream.next_seq - seq) as usize;
                    if overlap < tcp_payload_raw.len() {
                        stream
                            .stream_data
                            .extend_from_slice(&tcp_payload_raw[overlap..]);
                        stream.next_seq = seq + tcp_payload_raw.len() as u32;
                        is_contiguous = true;

                        while let Some(next_data) = stream.buffered.remove(&stream.next_seq) {
                            stream.stream_data.extend_from_slice(&next_data);
                            stream.next_seq += next_data.len() as u32;
                        }
                    }
                }

                if stream.stream_data.len() > 5 * 1024 * 1024 {
                    stream.stream_data.truncate(5 * 1024 * 1024);
                }

                if is_contiguous {
                    reassembled_payload = stream.stream_data.clone();
                } else {
                    reassembled_payload = Vec::new();
                }
            });
        }
    }

    let tcp_payload = &reassembled_payload;

    let summary = if syn && !ack {
        "TCP Connection opened (3-way handshake)".into()
    } else if syn && ack {
        "TCP SYN-ACK — handshake in progress".into()
    } else if fin {
        "TCP Connection closing (FIN)".into()
    } else if rst {
        "TCP Connection reset (RST)".into()
    } else if !tcp_payload.is_empty() {
        // Try application-layer dissection by well-known port.
        let on = |p: u16| src_port == p || dst_port == p;
        if on(80) {
            // h2c with prior knowledge sends the HTTP/2 preface straight to
            // port 80 — check for it before assuming HTTP/1.x.
            if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
                return h2;
            }
            return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(443) {
            return tls::dissect_tls(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(22) {
            return ssh::dissect_ssh(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(21) {
            return ftp::dissect_ftp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(25) || on(587) {
            return smtp::dissect_smtp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(143) {
            return imap::dissect_imap(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(110) {
            return pop3::dissect_pop3(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(23) {
            return telnet::dissect_telnet(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3389) {
            return rdp::dissect_rdp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Database wire protocols (ROADMAP §3.4).
        if on(5432) {
            return postgres::dissect_postgres(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3306) {
            return mysql::dissect_mysql(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(27017) {
            return mongodb::dissect_mongodb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6379) {
            return redis::dissect_redis(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(9042) {
            return cassandra::dissect_cassandra(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Industrial / OT protocols (ROADMAP §3.5).
        if on(502) {
            return modbus::dissect_modbus(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(20000) {
            return dnp3::dissect_dnp3(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(44818) {
            return enip::dissect_enip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4840) {
            return opcua::dissect_opcua(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Security / auth / VPN protocols (ROADMAP §3.7).
        if on(88) {
            return kerberos::dissect_kerberos(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(389) {
            return ldap::dissect_ldap(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1194) {
            return openvpn::dissect_openvpn(src_ip, dst_ip, src_port, dst_port, tcp_payload, true);
        }
        // IoT messaging (ROADMAP §3.8).
        if on(1883) {
            return mqtt::dissect_mqtt(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Operator / routing protocols (ROADMAP §3.3).
        if on(179) {
            return bgp::dissect_bgp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // SMB, TDS, AMQP, Kafka
        if on(445) {
            return smb::dissect_smb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1433) {
            return tds::dissect_tds(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5672) {
            return amqp::dissect_amqp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(9092) {
            return kafka::dissect_kafka(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Media, chat, remote-desktop and legacy text services over TCP.
        if on(554) {
            return rtsp::dissect_rtsp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6667) || on(6697) {
            return irc::dissect_irc(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5900) {
            return rfb::dissect_rfb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(43) {
            return whois::dissect_whois(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(119) {
            return nntp::dissect_nntp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Legacy text services, proxies, chat, caching and version control.
        if on(79) {
            return finger::dissect_finger(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1080) {
            return socks::dissect_socks(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5222) || on(5269) {
            return xmpp::dissect_xmpp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(9418) {
            return git::dissect_git(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(11211) {
            return memcached::dissect_memcached(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // BitTorrent uses a port range and an unmistakable handshake, so match
        // either the well-known ports or the handshake bytes on any port.
        if (6881..=6889).contains(&src_port)
            || (6881..=6889).contains(&dst_port)
            || bittorrent::looks_like_bittorrent(tcp_payload)
        {
            return bittorrent::dissect_bittorrent(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // AAA (TACACS+, Diameter) and legacy remote login.
        if on(49) {
            return tacacs::dissect_tacacs(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3868) {
            return diameter::dissect_diameter(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(513) {
            return rlogin::dissect_rlogin(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Storage, streaming, SMS gateways, SDN and message brokers.
        if on(3260) {
            return iscsi::dissect_iscsi(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1935) {
            return rtmp::dissect_rtmp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2775) {
            return smpp::dissect_smpp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6653) {
            return openflow::dissect_openflow(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4222) {
            return nats::dissect_nats(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(61613) {
            return stomp::dissect_stomp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Industrial control, healthcare, finance and MPLS label signalling.
        if on(102) {
            // S7comm and IEC 61850 MMS share port 102 over TPKT/COTP; the byte
            // after the COTP header tells them apart.
            if mms::looks_like_mms(tcp_payload) {
                return mms::dissect_mms(src_ip, dst_ip, src_port, dst_port, tcp_payload);
            }
            return s7comm::dissect_s7comm(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2404) {
            return iec104::dissect_iec104(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(104) || on(11112) {
            return dicom::dissect_dicom(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(646) {
            return ldp::dissect_ldp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // HL7 (MLLP) and FIX ride assorted ports; recognise them by content too.
        if on(2575) || hl7::looks_like_hl7(tcp_payload) {
            return hl7::dissect_hl7(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if fix::looks_like_fix(tcp_payload) {
            return fix::dissect_fix(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // RPC/NFS, metrics and job queues.
        if on(111) || on(2049) {
            return rpc::dissect_rpc(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2003) {
            return graphite::dissect_graphite(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4730) {
            return gearman::dissect_gearman(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(11300) {
            return beanstalk::dissect_beanstalk(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Display, file sync, version control and document DB.
        if (6000..=6005).contains(&src_port) || (6000..=6005).contains(&dst_port) {
            return x11::dissect_x11(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(873) {
            return rsync::dissect_rsync(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3690) {
            return svn::dissect_svn(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(28015) {
            return rethinkdb::dissect_rethinkdb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Search, monitoring, messaging and key-value DB.
        if on(9300) {
            return elasticsearch::dissect_elasticsearch(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_payload,
            );
        }
        if on(10050) || on(10051) {
            return zabbix::dissect_zabbix(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4150) {
            return nsq::dissect_nsq(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3000) {
            return aerospike::dissect_aerospike(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Automotive (SOME/IP, DoIP), Apple filing, P2P, gaming and voice.
        if (30490..=30510).contains(&src_port) || (30490..=30510).contains(&dst_port) {
            return someip::dissect_someip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(13400) {
            return doip::dissect_doip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(548) {
            return afp::dissect_afp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6346) {
            return gnutella::dissect_gnutella(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4662) {
            return edonkey::dissect_edonkey(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(25565) {
            return minecraft::dissect_minecraft(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(64738) {
            return mumble::dissect_mumble(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Carrier VoIP, remote desktop/thin client, backup and Windows RPC.
        if on(2944) || on(2945) {
            return megaco::dissect_megaco(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2855) {
            return msrp::dissect_msrp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4172) {
            return pcoip::dissect_pcoip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1494) {
            return ica::dissect_ica(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(10000) {
            return ndmp::dissect_ndmp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(135) {
            return dcerpc::dissect_dcerpc(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(1723) {
            return pptp::dissect_pptp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4899) {
            return radmin::dissect_radmin(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2000) {
            return skinny::dissect_skinny(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Routing telemetry/security, monitoring and data platforms.
        if on(11019) {
            return bmp::dissect_bmp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(323) {
            return rpkirtr::dissect_rpkirtr(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5666) {
            return nrpe::dissect_nrpe(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(7687) {
            return bolt::dissect_bolt(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(9000) {
            return clickhouse::dissect_clickhouse(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6650) {
            return pulsar::dissect_pulsar(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(61616) {
            return openwire::dissect_openwire(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Coordination, big-data RPC and log shipping.
        if on(2181) {
            return zookeeper::dissect_zookeeper(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(8020) {
            return hadooprpc::dissect_hadooprpc(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(24224) {
            return fluentd::dissect_fluentd(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5044) {
            return beats::dissect_beats(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(2514) {
            return relp::dissect_relp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Mail-side scanning/filtering and classic Unix services.
        if on(3310) {
            return clamav::dissect_clamav(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(783) {
            return spamd::dissect_spamd(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(4190) {
            return managesieve::dissect_managesieve(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_payload,
            );
        }
        if on(515) {
            return lpd::dissect_lpd(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(113) {
            return ident::dissect_ident(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(70) {
            return gopher::dissect_gopher(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(631) {
            return ipp::dissect_ipp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(512) {
            return rexec::dissect_rexec(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(6566) {
            return sane::dissect_sane(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Enterprise databases.
        if on(1521) {
            return tns::dissect_tns(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // 50000 and 33060 sit inside the ephemeral port range, so these also
        // require the protocol's own framing before claiming a flow.
        if on(50000) && drda::looks_like_drda(tcp_payload) {
            return drda::dissect_drda(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(3050) {
            return firebird::dissect_firebird(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(33060) && mysqlx::looks_like_mysqlx(tcp_payload) {
            return mysqlx::dissect_mysqlx(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(8087) {
            return riak::dissect_riak(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // Telemetry feeds: navigation, aviation and amateur radio.
        if on(10110) && nmea::looks_like_nmea(tcp_payload) {
            return nmea::dissect_nmea(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(30005) && adsb::looks_like_adsb(tcp_payload) {
            return adsb::dissect_adsb(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(14580) {
            return aprs::dissect_aprs(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // TCP 514 is rsh; syslog's 514 is UDP and handled in the UDP dissector.
        if on(514) {
            return rsh::dissect_rsh(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // SPICE consoles use varied ports; recognise the link magic structurally.
        if spice::looks_like_spice(tcp_payload) {
            return spice::dissect_spice(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // ZMTP/ZeroMQ uses arbitrary ports; recognise its greeting structurally.
        if zmtp::looks_like_zmtp(tcp_payload) {
            return zmtp::dissect_zmtp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // WebSocket and HTTP/2 (h2c) live on no fixed port (an HTTP connection
        // is upgraded in place, or the h2c preface opens any port), so their
        // traffic can show up anywhere. Route upgrade handshakes through the
        // HTTP dissector even off port 80, and report strictly-validated
        // WebSocket frame chains / HTTP/2 frame chains as themselves.
        // upgrade_note only reads the header block, so validate just the
        // first 2 KiB instead of UTF-8-scanning every payload (ROADMAP §4.1).
        let head = &tcp_payload[..tcp_payload.len().min(2048)];
        if let Ok(text) = std::str::from_utf8(head) {
            if websocket::upgrade_note(text).is_some() || http2::upgrade_note(text).is_some() {
                return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
            }
        }
        if let Some(ws) = websocket::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
            return ws;
        }
        if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
            return h2;
        }
        if let Some(ntlm) = ntlm::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
            return ntlm;
        }
        // User-defined plugins claim what no built-in dissector recognised
        // (see crate::plugins) — they never shadow the protocols above.
        if let Some(p) = crate::plugins::try_dissect(
            crate::plugins::TransportKind::Tcp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_payload,
        ) {
            return p;
        }
        format!("TCP — {} bytes of payload", tcp_payload.len())
    } else {
        "TCP — no payload (keep-alive or ACK)".into()
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{build_tcp_packet, TcpFlags};

    #[test]
    fn tcp_syn() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            &[],
        );
        // We need only the TCP portion (after IP header)
        // IP header is 20 bytes, so skip that
        let ip_data = &data[14..]; // skip ethernet
        let (_ip_src, _ip_dst, _proto, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.src_port, Some(12345));
        assert_eq!(result.dst_port, Some(80));
        assert_eq!(result.summary, "TCP Connection opened (3-way handshake)");
    }

    #[test]
    fn tcp_fin() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                fin: true,
                ..Default::default()
            },
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP Connection closing (FIN)");
    }

    #[test]
    fn tcp_rst() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                rst: true,
                ..Default::default()
            },
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP Connection reset (RST)");
    }

    #[test]
    fn tcp_syn_ack() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP SYN-ACK — handshake in progress");
    }

    #[test]
    fn tcp_data_no_payload() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            &[],
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.summary, "TCP — no payload (keep-alive or ACK)");
    }

    #[test]
    fn tcp_malformed() {
        let result = dissect_tcp(None, None, &[0; 3]);
        assert_eq!(result.protocol, Protocol::Unknown("malformed TCP".into()));
        assert!(result.src_port.is_none());
    }

    /// Run a payload through dissect_tcp on an arbitrary (non-well-known) port.
    fn dissect_payload_on_port_8080(payload: &[u8]) -> super::DissectedResult {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            8080,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            payload,
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        )
    }

    #[test]
    fn websocket_frames_detected_on_any_port() {
        // Unmasked text frame "hi": FIN|text, len 2.
        let result = dissect_payload_on_port_8080(&[0x81, 0x02, b'h', b'i']);
        assert_eq!(result.protocol, Protocol::WebSocket);
        assert_eq!(result.summary, "WebSocket Text — \"hi\"");
    }

    #[test]
    fn websocket_handshake_routed_to_http_on_any_port() {
        let req = b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\n\r\n";
        let result = dissect_payload_on_port_8080(req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(
            result.summary,
            "HTTP GET /chat (HTTP/1.1) — WebSocket handshake"
        );
    }

    #[test]
    fn plain_payload_on_odd_port_stays_tcp() {
        let result = dissect_payload_on_port_8080(b"just some application bytes");
        assert_eq!(result.protocol, Protocol::Tcp);
        assert!(result.summary.starts_with("TCP —"));
    }

    #[test]
    fn http2_frames_detected_on_any_port() {
        // SETTINGS ACK: len 0, type 0x4, flags 0x1, stream 0.
        let result = dissect_payload_on_port_8080(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]);
        assert_eq!(result.protocol, Protocol::Http2);
        assert_eq!(result.summary, "HTTP/2 SETTINGS ACK");
    }

    #[test]
    fn http2_preface_detected_on_port_80() {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            80,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Http2);
        assert_eq!(result.summary, "HTTP/2 connection preface");
    }

    #[test]
    fn grpc_message_detected_on_any_port() {
        // DATA frame (stream 1, END_STREAM) carrying one complete gRPC
        // message: flag 0 + length 3 + 3 payload bytes.
        let mut payload = vec![0, 0, 8, 0x0, 0x1, 0, 0, 0, 1];
        payload.extend([0u8, 0, 0, 0, 3, 7, 7, 7]);
        let result = dissect_payload_on_port_8080(&payload);
        assert_eq!(result.protocol, Protocol::Grpc);
        assert_eq!(
            result.summary,
            "gRPC message — 3 bytes (uncompressed) on stream 1"
        );
    }

    #[test]
    fn h2c_upgrade_routed_to_http_on_any_port() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";
        let result = dissect_payload_on_port_8080(req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(
            result.summary,
            "HTTP GET / (HTTP/1.1) — HTTP/2 upgrade (h2c)"
        );
    }

    #[test]
    fn tcp_reassembly_out_of_order() {
        clear_tcp_reassembler();
        let ip_src = Some("10.0.0.1".parse().unwrap());
        let ip_dst = Some("10.0.0.2".parse().unwrap());

        let p1 = etherparse::TcpHeader::new(12345, 80, 100, 1024);
        let mut f1 = Vec::new();
        p1.write(&mut f1).unwrap();
        f1.extend_from_slice(b"GET / HTTP/1.1\r\n");

        let p3 = etherparse::TcpHeader::new(12345, 80, 133, 1024);
        let mut f3 = Vec::new();
        p3.write(&mut f3).unwrap();
        f3.extend_from_slice(b"\r\n");

        let p2 = etherparse::TcpHeader::new(12345, 80, 116, 1024);
        let mut f2 = Vec::new();
        p2.write(&mut f2).unwrap();
        f2.extend_from_slice(b"Host: localhost\r\n");

        let r1 = dissect_tcp(ip_src, ip_dst, &f1);
        assert_eq!(r1.protocol, Protocol::Http);

        let r3 = dissect_tcp(ip_src, ip_dst, &f3);
        assert_ne!(r3.protocol, Protocol::Http);

        let r2 = dissect_tcp(ip_src, ip_dst, &f2);
        assert_eq!(r2.protocol, Protocol::Http);
        assert!(r2.summary.contains("HTTP GET /"));
    }
}
