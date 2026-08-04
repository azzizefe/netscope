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
    someip, syslog, tls, websocket, zmtp, DissectedResult,
};

/// Ports claimed by a dissector that validates nothing, on a number the vendor
/// is not known to own.
///
/// Every entry was added by the same batch of industrial and edge-AI
/// dissectors: each reads fixed offsets and formats them as a session id, a
/// message type and a counter, without checking a single byte first. An exact
/// port match outranks every structural sniff, so on these ports ordinary
/// traffic came back wearing a PLC protocol's name.
///
/// Kept as a list rather than folded into `bindings` because it is a statement
/// about *confidence in the port*, not about the protocol. The right way off
/// this list is a real signature — then the dissector can claim its port
/// outright, the way the ones not listed here do.
const UNVERIFIED_VENDOR_PORTS: &[u16] = &[
    2020,  // sinumerik_nck_channel — SINUMERIK talks S7 on 102; IANA has xinupageserver
    4121,  // interbus — a fieldbus, not an IP protocol; IANA has e-Builder
    4410,  // tia_portal_online_diag — TIA Portal diagnostics ride S7comm on 102
    4841,  // studio5000_online_comm — IANA `opcua-tls`; Studio 5000 uses EtherNet/IP 44818
    6002,  // factorytalk_view_hmi — X11 display :2
    8001,  // edge_inference_onnx — generic alternate HTTP
    8087,  // twincat_scope_view — IANA simplifymedia; also Riak protobuf
    8090,  // simatic_hmi_smartsrv — generic alternate HTTP
    8501,  // edge_tensorflow_lite — TensorFlow Serving's REST port, which is HTTP
    8910,  // bosch_nexeed_edge — IANA manyone-http
    11157, // b_r_automation_pvi — B&R PVI is documented on 11159/11160
];

/// Whether the payload opens an HTTP/1.x request or response.
///
/// Only the start line is checked, and only exactly: a request is a known
/// method, a space, a target, and ` HTTP/1.`; a response is `HTTP/1.` outright.
/// Nothing here should ever fire on binary framing.
fn looks_like_http_message(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
    ];
    if payload.starts_with(b"HTTP/1.") {
        return true;
    }
    let Some(method) = METHODS.iter().find(|m| payload.starts_with(m)) else {
        return false;
    };
    // The version token has to be on the same line, or this is a payload that
    // merely happens to begin with those four bytes.
    let line_end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len())
        .min(8192);
    payload[method.len()..line_end]
        .windows(7)
        .any(|w| w == b"HTTP/1.")
}

/// Whether the payload opens a TLS record.
///
/// Content type in the assigned range, a `3.x` legacy version, and a record
/// length within the 2^14 + expansion ceiling TLS itself imposes. Three
/// independent constraints, which is what keeps this from firing on arbitrary
/// binary that happens to start with 0x16.
fn looks_like_tls_record(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }
    let content_type = payload[0];
    // change_cipher_spec, alert, handshake, application_data.
    if !(0x14..=0x17).contains(&content_type) {
        return false;
    }
    if payload[1] != 0x03 || payload[2] > 0x04 {
        return false;
    }
    let len = u16::from_be_bytes([payload[3], payload[4]]);
    len > 0 && len <= 0x4800
}

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
                        stream.next_seq = seq.wrapping_add(tcp_payload_raw.len() as u32);
                        is_contiguous = true;
                    }

                    while let Some(next_data) = stream.buffered.remove(&stream.next_seq) {
                        stream.stream_data.extend_from_slice(&next_data);
                        stream.next_seq = stream.next_seq.wrapping_add(next_data.len() as u32);
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
                        stream.next_seq = seq.wrapping_add(tcp_payload_raw.len() as u32);
                        is_contiguous = true;

                        while let Some(next_data) = stream.buffered.remove(&stream.next_seq) {
                            stream.stream_data.extend_from_slice(&next_data);
                            stream.next_seq = stream.next_seq.wrapping_add(next_data.len() as u32);
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
        // 0. A vendor port nothing here can verify does not get to swallow a
        //    payload that is unmistakably something else.
        //
        //    These ports were bound to industrial and edge-AI dissectors that
        //    read fixed offsets and validate nothing, so whatever arrived came
        //    back as "TagSubscribe tags:3" or "session:16030100 InferenceReq".
        //    Because an exact-port match outranks every structural sniff, real
        //    HTTP and real TLS on any of them were relabelled — and several of
        //    the ports are not the vendor's at all: 4841 is IANA `opcua-tls`,
        //    6002 is X11 display :2, and 8001/8087/8090/8910 are ordinary
        //    alternate-HTTP ports.
        //
        //    Rather than guess at each vendor's framing, which needs a spec
        //    none of these has, this rules out the two protocols that are
        //    cheap to recognise and impossible to mistake. A vendor protocol
        //    that genuinely starts with `GET / HTTP/1.1` does not exist.
        //    FANUC FOCAS (8193) and OMRON FINS (9600) are deliberately absent:
        //    both are the vendor's real, documented port.
        if UNVERIFIED_VENDOR_PORTS.contains(&src_port)
            || UNVERIFIED_VENDOR_PORTS.contains(&dst_port)
        {
            if looks_like_http_message(tcp_payload) {
                return http::dissect_http(src_ip, dst_ip, src_port, dst_port, tcp_payload);
            }
            if looks_like_tls_record(tcp_payload) {
                return tls::dissect_tls(src_ip, dst_ip, src_port, dst_port, tcp_payload);
            }
        }
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

    /// A vendor port whose claim nothing can verify must not swallow HTTP.
    ///
    /// Every one of these ports was bound to an industrial or edge-AI
    /// dissector that reads fixed offsets and validates nothing, and an exact
    /// port match outranks every structural sniff — so `GET / HTTP/1.1` on any
    /// of them came back as, for instance, "FactoryTalk View HMI — session:4745
    /// TagSubscribe tags:2074". Several of the ports are not the vendor's at
    /// all: 4841 is IANA `opcua-tls`, 6002 is X11 display :2, and 8001, 8087,
    /// 8090 and 8910 are ordinary alternate-HTTP ports.
    #[test]
    fn an_unverified_vendor_port_does_not_swallow_http() {
        let http = b"GET /index.html HTTP/1.1\r\nHost: plant.local\r\n\r\n";
        for &port in UNVERIFIED_VENDOR_PORTS {
            let protocol = dissect_on_port(port, http).protocol;
            assert_eq!(
                protocol,
                Protocol::Http,
                "port {port} claimed an HTTP request as {protocol:?}",
            );
        }
    }

    /// The same for TLS, which is the other thing these ports actually carry.
    #[test]
    fn an_unverified_vendor_port_does_not_swallow_tls() {
        // A ClientHello record header: handshake, TLS 1.0 legacy version, a
        // length inside the record ceiling, then the handshake body.
        let mut tls = vec![
            0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28, 0x03, 0x03,
        ];
        tls.extend_from_slice(&[0u8; 32]);
        for &port in UNVERIFIED_VENDOR_PORTS {
            let protocol = dissect_on_port(port, &tls).protocol;
            assert_eq!(
                protocol,
                Protocol::Tls,
                "port {port} claimed a TLS record as {protocol:?}",
            );
        }
    }

    /// The guards must not fire on the vendor framing they sit in front of.
    ///
    /// Both are deliberately narrow — three independent constraints for TLS, a
    /// method and a version token on one line for HTTP — because a guard that
    /// over-matches would take the traffic these dissectors are for.
    #[test]
    fn the_http_and_tls_guards_do_not_claim_binary_framing() {
        // The shape these vendor dissectors expect: a session id, a message
        // type, a counter. Starts with 0x16 in the third case on purpose.
        for framing in [
            &[0x00u8, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0x04][..],
            &[0xde, 0xad, 0xbe, 0xef, 0x07, 0x02, 0x00, 0x10][..],
            &[0x16, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04][..],
            b"GETTING STARTED\r\n",
            b"POSTGRES",
        ] {
            assert!(
                !looks_like_http_message(framing),
                "HTTP guard claimed {framing:02x?}",
            );
            assert!(
                !looks_like_tls_record(framing),
                "TLS guard claimed {framing:02x?}",
            );
        }
    }

    /// An unguarded dissector on a port inside the ephemeral range relabels
    /// ordinary traffic, because the binding table matches source ports too.
    /// 51000-51002 held three edge-AI dissectors that validated nothing, so a
    /// connection assigned 51000 as its source port was reported as PyTorch
    /// Mobile inference. Nothing may claim a bare payload on those ports again.
    ///
    /// 41100, 44819, 48400 and 48898/48899 were the second wave — Rexroth Open
    /// Core, FactoryTalk Edge and TwinCAT Analytics, each formatting fixed
    /// offsets of any payload into a session id and an opcode. They are listed
    /// here so re-adding one without a content guard fails immediately rather
    /// than at the next audit.

    #[test]
    fn an_ephemeral_source_port_is_not_a_protocol() {
        for port in [51000u16, 51001, 51002, 41100, 44819, 48400, 48898, 48899] {
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
        assert_eq!(result.summary, "TCP — no payload (keep-alive or ACK)");
    }

    /// A sequence number close to the top of the u32 space plus a payload wraps
    /// — that is how TCP is specified, and every long-lived connection does it.
    /// The reassembler advanced `next_seq` with a plain `+`, so a debug build
    /// panicked with "attempt to add with overflow" and a release build silently
    /// kept a wrong offset. `cargo fuzz` found it in 60 seconds; no fixture had
    /// ever carried a sequence number that high.
    #[test]
    fn a_sequence_number_near_the_wrap_does_not_panic() {
        let mut frame = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            41001,
            41002,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            b"payload that pushes the sequence past the end",
        );
        // Sequence number lives 4 bytes into the TCP header, which starts after
        // the 14-byte ethernet and 20-byte IPv4 headers.
        let seq_at = 14 + 20 + 4;
        frame[seq_at..seq_at + 4].copy_from_slice(&(u32::MAX - 4).to_be_bytes());

        let (_s, _d, _p, tcp_data) = crate::dissectors::ip::dissect_ipv4(&frame[14..]);
        let result = dissect_tcp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &tcp_data,
        );
        assert_eq!(result.protocol, Protocol::Tcp);
    }
}
