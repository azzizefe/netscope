// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::models::Protocol;

use super::{
    amqp1, bindings, consul_rpc, drbd, fix, hl7, http, http2, iec101, memcached_bin, milter,
    modbus_ascii, modbus_rtu, ntlm, opc_ua_dpi, openvpn, redis_cluster, schneider_ecostruxure_edge,
    someip, syslog, websocket, zmtp, DissectedResult,
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
        // 1. Ports that need more than a port number to decide. Each of these
        //    either picks between two protocols that share a port, or sits in
        //    the ephemeral range and must see its own framing before claiming
        //    the flow. See `bindings` for the full precedence order.
        if on(80) {
            // h2c with prior knowledge sends the HTTP/2 preface straight to
            // port 80 — check for it before assuming HTTP/1.x.
            if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
                return h2;
            }
            return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(5672) && amqp1::looks_like_amqp1(tcp_payload) {
            // AMQP 1.0 and 0-9-1 are different protocols sharing a port, and
            // reading one as the other produces nonsense rather than nothing.
            return amqp1::dissect_amqp1(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(11211) && memcached_bin::looks_like_binary(tcp_payload) {
            // The binary protocol shares 11211 with the text one, and is what
            // client libraries actually send.
            return memcached_bin::dissect_memcached_bin(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_payload,
            );
        }
        if on(102) {
            // TPKT/COTP on port 102 — dissector modules unavailable.
        }
        if on(2000) {
            // Mercurial on port 2000 — dissector module unavailable.
        }
        if on(1194) {
            // OpenVPN shares a port number across TCP and UDP; the flag says which.
            return openvpn::dissect_openvpn(src_ip, dst_ip, src_port, dst_port, tcp_payload, true);
        }
        // 8080 is the HTTP alternate port, which the EcoStruxure gateway's own
        // web UI also serves — so the framing decides, and ordinary traffic on
        // 8080 is not relabelled as a Schneider protocol.
        //
        // HTTP/2 goes first because it is the stronger test: a frame chain has
        // to validate end to end, whereas EcoStruxure has no magic and only a
        // message-type byte to offer. An HTTP/2 DATA frame header imitates that
        // byte exactly — END_STREAM is 0x01, which is also "Telemetry".
        if on(8080) {
            if let Some(h2) = http2::try_dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload) {
                return h2;
            }
            if schneider_ecostruxure_edge::looks_like_schneider_ecostruxure_edge(tcp_payload) {
                return schneider_ecostruxure_edge::dissect_schneider_ecostruxure_edge(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    tcp_payload,
                );
            }
        }
        // 8891 is Postfix and OpenDKIM's convention rather than an assignment,
        // so the framing has to agree before the flow is claimed.
        if on(8891) && milter::looks_like_milter(tcp_payload) {
            return milter::dissect_milter(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // The same gateway pattern as Modbus RTU: a serial telecontrol link
        // forwarded onto the -104 port unchanged. FT1.2 repeats its length and
        // start bytes, so the framing decides and -104 is not shadowed.
        if on(2404) && iec101::looks_like_iec101(tcp_payload) {
            return iec101::dissect_iec101(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // A serial gateway forwards RTU frames onto 502 unchanged. They are
        // not Modbus TCP and do not parse as it, so RTU is tried first — its
        // CRC is decisive, and a real Modbus TCP frame will not satisfy it.
        if on(502) && modbus_rtu::looks_like_modbus_rtu(tcp_payload) {
            return modbus_rtu::dissect_modbus_rtu(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if on(502) && modbus_ascii::looks_like_modbus_ascii(tcp_payload) {
            return modbus_ascii::dissect_modbus_ascii(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_payload,
            );
        }
        // 8300 is Consul's convention rather than an assignment, and the type
        // byte only leads the first segment of a connection — so a mid-stream
        // segment is left to the generic TCP summary rather than having a
        // random byte read as a protocol type.
        if on(8300) && consul_rpc::looks_like_consul_rpc(tcp_payload) {
            return consul_rpc::dissect_consul_rpc(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }

        // TCP 514 is assigned to rsh, but syslog-over-TCP squats there in
        // practice and is far more common on a modern network. The two are
        // trivially distinguishable, so let the content decide rather than
        // giving the port to whichever protocol was registered first.
        if on(514) && syslog::looks_like_syslog(tcp_payload) {
            return syslog::dissect_syslog(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }

        // 2. Exact well-known port.
        if let Some(dissect) = bindings::tcp(src_port, dst_port) {
            return dissect(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }

        // 3. Protocols that occupy a range rather than a single port.
        let in_range =
            |r: std::ops::RangeInclusive<u16>| r.contains(&src_port) || r.contains(&dst_port);
        if in_range(30490..=30510) {
            return someip::dissect_someip(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }

        // 4. Protocols with no fixed port at all, recognised by their framing.
        //    These run last so a well-known port always wins over a heuristic.
        if hl7::looks_like_hl7(tcp_payload) {
            return hl7::dissect_hl7(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        if fix::looks_like_fix(tcp_payload) {
            return fix::dissect_fix(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // A DRBD resource is put on whatever port its configuration names,
        // climbing from 7788 as resources are added, so there is no port to
        // bind — but each header layout carries a genuine magic.
        if drbd::looks_like_drbd(tcp_payload) {
            return drbd::dissect_drbd(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // The Redis cluster bus has no port of its own — it is the data port
        // plus ten thousand, so it moves whenever the data port does. The
        // "RCmb" signature is what identifies it wherever it lands.
        if redis_cluster::looks_like_cluster_bus(tcp_payload) {
            return redis_cluster::dissect_redis_cluster(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_payload,
            );
        }
        if zmtp::looks_like_zmtp(tcp_payload) {
            return zmtp::dissect_zmtp(src_ip, dst_ip, src_port, dst_port, tcp_payload);
        }
        // OPC UA binary on a port that is not 4840. Plant deployments move it
        // constantly — a server per line, or a gateway multiplexing several —
        // and until this ran those sessions were reported as bare TCP. Port
        // 4840 is unaffected: the table above matched it before reaching here,
        // so `opcua` still owns the standard port and this only picks up what
        // would otherwise have gone unrecognised.
        //
        // The signature is strong enough to sniff on: three ASCII bytes from a
        // closed set of seven message types, a chunk byte that must be F, C or
        // A, and a length field that has to agree with the frame.
        if opc_ua_dpi::looks_like_opcua_dpi(tcp_payload) {
            return opc_ua_dpi::dissect_opc_ua_dpi(src_ip, dst_ip, src_port, dst_port, tcp_payload);
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
            // An upgrade handshake is still an ordinary HTTP request on the
            // wire, so it goes through the HTTP dissector and comes back
            // labelled with what it is upgrading to. Reporting it as WebSocket
            // or HTTP/2 outright loses the request line, which is the half of
            // the handshake that says what was asked for.
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

    /// An OPC UA `HEL` chunk: three ASCII message-type bytes, the `F` chunk
    /// marker, and a little-endian length that agrees with the frame.
    fn opcua_hello(extra: usize) -> Vec<u8> {
        let len = 8 + extra;
        let mut msg = Vec::from(b"HELF");
        msg.extend_from_slice(&(len as u32).to_le_bytes());
        msg.resize(len, 0);
        msg
    }

    fn dissect_on_port(dst_port: u16, payload: &[u8]) -> DissectedResult {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            51000,
            dst_port,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            payload,
        );
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(&data[14..]);
        dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        )
    }

    /// Plants move OPC UA off 4840 constantly — one server per line, or a
    /// gateway multiplexing several. Until the structural sniff was wired,
    /// every one of those sessions came back as bare TCP.
    #[test]
    fn opc_ua_is_recognised_off_its_standard_port() {
        let result = dissect_on_port(49320, &opcua_hello(24));
        assert_ne!(
            result.protocol,
            Protocol::Tcp,
            "OPC UA on a non-standard port fell through to bare TCP",
        );
    }

    /// The sniff runs after the port table, so 4840 is untouched by it — that
    /// port belongs to `opcua`, which is a different dissector with different
    /// output. Adding a heuristic must not quietly re-route the standard port.
    #[test]
    fn port_4840_still_belongs_to_the_port_table() {
        let dpi = dissect_on_port(49320, &opcua_hello(24)).protocol;
        let standard = dissect_on_port(4840, &opcua_hello(24)).protocol;
        assert_ne!(
            standard, dpi,
            "the structural sniff took over port 4840 from the binding table",
        );
    }

    /// The guard must not claim traffic that merely happens to be long enough.
    /// A dissector wired by framing alone is one loose check away from renaming
    /// unrelated flows.
    ///
    /// This asserts only that OPC UA does not claim them — an HTTP request is
    /// still expected to come back as HTTP, so "nothing recognised it" would be
    /// the wrong assertion.
    #[test]
    fn the_opc_ua_sniff_does_not_claim_arbitrary_payloads() {
        for payload in [
            &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &[0u8; 64][..],
            // Right shape, wrong message type: `HELX` is not one of the seven.
            &b"HELX\x20\x00\x00\x00padding padding padding"[..],
            // Right message type, wrong chunk byte.
            &b"HELZ\x20\x00\x00\x00padding padding padding"[..],
        ] {
            assert_ne!(
                dissect_on_port(49321, payload).protocol,
                Protocol::OpcUaDpi,
                "the OPC UA sniff claimed a payload that is not OPC UA",
            );
        }
    }

    /// An unguarded dissector on a port inside the ephemeral range relabels
    /// ordinary traffic, because the binding table matches source ports too.
    /// 51000-51002 held three edge-AI dissectors that validated nothing, so a
    /// connection assigned 51000 as its source port was reported as PyTorch
    /// Mobile inference. Nothing may claim a bare payload on those ports again.
    #[test]
    fn an_ephemeral_source_port_is_not_a_protocol() {
        for port in [51000u16, 51001, 51002] {
            let protocol = dissect_on_port(port, &[0u8; 64]).protocol;
            assert_eq!(
                protocol,
                Protocol::Tcp,
                "port {port} claimed 64 zero bytes as {protocol:?}",
            );
        }
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

    /// Run a payload through the real dispatch path on a chosen port.
    fn dissect_payload_on_port(port: u16, payload: &[u8]) -> super::DissectedResult {
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            port,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            payload,
        );
        let (_s, _d, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(&data[14..]);
        dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        )
    }

    /// Two unrelated protocols share TCP 5672, so dispatch has to pick between
    /// them rather than giving the port to whichever was registered first.
    #[test]
    fn port_5672_splits_amqp_1_0_from_0_9_1() {
        let one_oh = dissect_payload_on_port(5672, b"AMQP\x00\x01\x00\x00");
        assert_eq!(one_oh.protocol, Protocol::Amqp1);

        // The 0-9-1 protocol header, and a 0-9-1 method frame, must both still
        // reach the original dissector.
        assert_eq!(
            dissect_payload_on_port(5672, b"AMQP\x00\x00\x09\x01").protocol,
            Protocol::Amqp
        );
        let method = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0A, 0x00, 0x0B, 0xCE,
        ];
        assert_eq!(
            dissect_payload_on_port(5672, &method).protocol,
            Protocol::Amqp
        );
    }

    /// Memcached's two protocols share 11211 and are told apart by a magic
    /// byte; the text form must not be swallowed by the binary dissector.
    #[test]
    fn port_11211_splits_binary_memcached_from_text() {
        let mut binary = vec![0x80, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00];
        binary.extend_from_slice(&3u32.to_be_bytes());
        binary.extend_from_slice(&[0u8; 12]);
        binary.extend_from_slice(b"abc");
        assert_eq!(
            dissect_payload_on_port(11211, &binary).protocol,
            Protocol::MemcachedBin
        );
        assert_eq!(
            dissect_payload_on_port(11211, b"get user:42\r\n").protocol,
            Protocol::Memcached
        );
    }

    /// The cluster bus has no port of its own, so it is found by signature —
    /// including on a port that belongs to something else entirely.
    #[test]
    fn the_redis_cluster_bus_is_found_by_signature() {
        let mut bus = b"RCmb".to_vec();
        bus.extend_from_slice(&2000u32.to_be_bytes());
        bus.extend_from_slice(&1u16.to_be_bytes());
        bus.extend_from_slice(&3u16.to_be_bytes()); // FAIL
        bus.extend_from_slice(&[b'a'; 40]);
        assert_eq!(
            dissect_payload_on_port(16379, &bus).protocol,
            Protocol::RedisCluster
        );
        // A well-known port still wins over the heuristic, as it must.
        assert_eq!(
            dissect_payload_on_port(6379, b"*1\r\n$4\r\nPING\r\n").protocol,
            Protocol::Redis
        );
    }

    /// 9P reaches its dissector through the port table.
    #[test]
    fn ninep_is_dispatched_on_its_port() {
        let mut ninep = 11u32.to_le_bytes().to_vec();
        ninep.push(110); // Twalk
        ninep.extend_from_slice(&7u16.to_le_bytes());
        ninep.extend_from_slice(&[0u8; 4]);
        let r = dissect_payload_on_port(564, &ninep);
        assert_eq!(r.protocol, Protocol::NineP);
        assert!(r.summary.contains("Twalk"));
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

    #[test]
    fn tcp_syn_with_payload_is_still_tcp() {
        clear_tcp_reassembler();
        let payload = b"GET / HTTP/1.1\r\n";
        let data = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            payload,
        );
        let ip_data = &data[14..];
        let (_src, _dst, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.summary, "TCP Connection opened (3-way handshake)");
    }

    #[test]
    fn tcp_overlap_adds_new_data_on_retransmit() {
        clear_tcp_reassembler();
        let ip_src = Some("10.0.0.1".parse().unwrap());
        let ip_dst = Some("10.0.0.2".parse().unwrap());

        // Use non-standard ports to avoid protocol dissector interference
        let p1 = etherparse::TcpHeader::new(54321, 54322, 100, 1024);
        let mut f1 = Vec::new();
        p1.write(&mut f1).unwrap();
        f1.extend_from_slice(b"Hello World");

        let p2 = etherparse::TcpHeader::new(54321, 54322, 105, 1024);
        let mut f2 = Vec::new();
        p2.write(&mut f2).unwrap();
        f2.extend_from_slice(b"World");

        let r1 = dissect_tcp(ip_src, ip_dst, &f1);
        assert_eq!(r1.protocol, Protocol::Tcp);

        // 100 + 11 = 111 (next_seq). seq=105, overlap = 111-105 = 6 >= 5
        // → entire payload is within already-received data → no new data
        let r2 = dissect_tcp(ip_src, ip_dst, &f2);
        assert_eq!(r2.protocol, Protocol::Tcp);
        assert_eq!(r2.summary, "TCP — no payload (keep-alive or ACK)");
    }

    #[test]
    fn tcp_seq_0_resets_reassembly_after_syn() {
        clear_tcp_reassembler();
        let ip_src = Some("10.0.0.1".parse().unwrap());
        let ip_dst = Some("10.0.0.2".parse().unwrap());

        // Use non-standard port so protocol dissection does not interfere
        let p1 = etherparse::TcpHeader::new(54321, 54322, 100, 1024);
        let mut f1 = Vec::new();
        p1.write(&mut f1).unwrap();
        f1.extend_from_slice(b"first data");

        let p2 = etherparse::TcpHeader::new(54321, 54322, 0, 1024);
        let mut f2 = Vec::new();
        p2.write(&mut f2).unwrap();
        f2.extend_from_slice(b"new data");

        let _r1 = dissect_tcp(ip_src, ip_dst, &f1);
        let r2 = dissect_tcp(ip_src, ip_dst, &f2);
        // seq=0 resets stream, so second payload should be delivered
        assert_eq!(r2.protocol, Protocol::Tcp);
    }

    #[test]
    fn tcp_header_minimal_without_options() {
        // Minimal 20-byte TCP header, no payload, data_offset=5
        let mut raw = vec![0u8; 20];
        raw[12] = 0x50; // data_offset = 5 (20 bytes), no flags
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &raw,
        );
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(
            result.summary,
            "TCP — no payload (keep-alive or ACK)"
        );
    }
}
