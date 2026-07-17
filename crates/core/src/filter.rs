// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Wireshark-style display filter language.
//!
//! Parses expressions like `ip.addr == 1.2.3.4 && tcp.port == 443`, `dns`,
//! `frame.len > 1000`, `udp.port != 53 or http` into an AST and evaluates them
//! against a [`Packet`]. Parsing is fallible on purpose: callers that offer a
//! "type anything" box (TUI/desktop) fall back to a plain substring search when
//! [`Filter::parse`] returns [`Err`], so free-text search keeps working.
//!
//! ## Supported grammar
//!
//! - **Protocol predicates** (bare words): `tcp`, `udp`, `icmp`, `arp`, `ip`,
//!   `ipv4`, `ipv6`, `dns`, `http`, `tls`, `dhcp`, `ntp`, `mdns`, `snmp`,
//!   `quic`, `sip`, `ssh`, `ftp`, `smtp`, `imap`, `pop3`, `telnet`, `rdp`,
//!   `wlan` / `wifi` / `802.11`, `websocket` / `ws`, `vxlan`, `http2`, `grpc`.
//! - **Fields**: `ip.addr`, `ip.src`, `ip.dst`, `port`, `tcp.port`,
//!   `udp.port`, `frame.len` (aliases: `len`, `length`).
//! - **Protocol fields** (parsed from the captured frame bytes):
//!   `tcp.flags.syn` / `.ack` / `.fin` / `.rst` / `.psh` (compare to `1`/`0`),
//!   `http.request.method`, `http.request.uri`, `http.host`,
//!   `http.response.code`, `dns.qry.name`, the TLS fingerprints
//!   `tls.ja3` / `ja3`, `tls.ja4` / `ja4`, `tls.ja3s` / `ja3s` (recomputed from
//!   the handshake bytes), and `info` (the summary column). Text fields compare
//!   case-insensitively.
//! - **Comparisons**: `==` `!=` `>` `<` `>=` `<=`, plus `contains` (substring
//!   over the field's text form).
//! - **Logic**: `&&`/`and`, `||`/`or`, `!`/`not`, and parentheses.

use std::net::IpAddr;

use crate::flows::Transport;
use crate::models::{Packet, Protocol};

/// Protocol tokens accepted as bare predicates (e.g. `tcp`, `dns`).
const KNOWN_PROTOS: &[&str] = &[
    "ip",
    "ipv4",
    "ipv6",
    "tcp",
    "udp",
    "icmp",
    "arp",
    "dns",
    "http",
    "tls",
    "dhcp",
    "ntp",
    "mdns",
    "snmp",
    "quic",
    "sip",
    "ssh",
    "ftp",
    "smtp",
    "imap",
    "pop3",
    "telnet",
    "rdp",
    "wlan",
    "wifi",
    "802.11",
    "usb",
    "bluetooth",
    "hci",
    "can",
    "websocket",
    "ws",
    "vxlan",
    "http2",
    "grpc",
    "ntlm",
    "rtp",
    "rtcp",
    "qpack",
    "http3",
    "syslog",
    "tftp",
    "ssdp",
    "stun",
    "llmnr",
    "rtsp",
    "irc",
    "rfb",
    "vnc",
    "whois",
    "nntp",
    "sctp",
    "gre",
    "igmp",
    "dhcpv6",
    "rip",
    "nbns",
    "socks",
    "memcached",
    "bittorrent",
    "git",
    "xmpp",
    "finger",
    "vrrp",
    "pim",
    "eigrp",
    "pppoe",
    "eapol",
    "l2tp",
    "gtp",
    "rmcp",
    "ipmi",
    "wsd",
    "tacacs",
    "diameter",
    "rlogin",
    "dccp",
    "dtls",
    "netflow",
    "ipfix",
    "sflow",
    "bfd",
    "hsrp",
    "iscsi",
    "rtmp",
    "smpp",
    "openflow",
    "nats",
    "stomp",
    "profinet",
    "wol",
    "glbp",
    "wccp",
    "mgcp",
    "nbds",
    "dicom",
    "hl7",
    "fix",
    "s7comm",
    "iec104",
    "ldp",
    "goose",
    "ptp",
    "rsvp",
    "isakmp",
    "ike",
    "geneve",
    "capwap",
    "teredo",
    "gvcp",
    "rpc",
    "nfs",
    "portmap",
    "graphite",
    "gearman",
    "beanstalk",
];

#[derive(Debug, Clone, PartialEq)]
pub struct FilterError(pub String);

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid filter: {}", self.0)
    }
}

impl std::error::Error for FilterError {}

/// A compiled display filter.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    ast: Expr,
}

impl Filter {
    /// Parse a filter expression. Returns [`Err`] for anything that isn't valid
    /// filter syntax (unknown field, dangling operator, unbalanced parens…),
    /// which the UI treats as a signal to fall back to substring search.
    pub fn parse(input: &str) -> Result<Filter, FilterError> {
        let tokens = lex(input)?;
        if tokens.is_empty() {
            return Err(FilterError("empty filter".into()));
        }
        let mut parser = Parser { tokens, pos: 0 };
        let ast = parser.parse_or()?;
        if parser.pos != parser.tokens.len() {
            return Err(FilterError("trailing tokens".into()));
        }
        Ok(Filter { ast })
    }

    /// Does `pkt` match this filter?
    pub fn matches(&self, pkt: &Packet) -> bool {
        self.ast.eval(pkt)
    }
}

// ---- AST ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    IpAny,
    IpSrc,
    IpDst,
    PortAny,
    TcpPort,
    UdpPort,
    FrameLen,
    /// One TCP flag bit (SYN/ACK/FIN/RST/PSH); evaluates to `1` or `0`.
    TcpFlag(u8),
    HttpMethod,
    HttpUri,
    HttpHost,
    HttpRespCode,
    DnsQryName,
    /// JA3 client fingerprint (MD5), recomputed from the TLS ClientHello.
    TlsJa3,
    /// JA4 client fingerprint (FoxIO), recomputed from the TLS ClientHello.
    TlsJa4,
    /// JA3S server fingerprint (MD5), recomputed from the TLS ServerHello.
    TlsJa3s,
    /// The human-readable summary ("Info" column).
    Info,
    RtpSsrc,
    RtpSeq,
    NtlmUser,
    NtlmDomain,
    NtlmWorkstation,
    TlsSni,
    Http3Method,
    Http3Status,
}

// TCP flag bit masks (RFC 9293, byte 13 of the TCP header).
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Num(u64),
    Ip(IpAddr),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Proto(String),
    Cmp(Field, CmpOp, Value),
}

impl Expr {
    fn eval(&self, pkt: &Packet) -> bool {
        match self {
            Expr::Or(a, b) => a.eval(pkt) || b.eval(pkt),
            Expr::And(a, b) => a.eval(pkt) && b.eval(pkt),
            Expr::Not(e) => !e.eval(pkt),
            Expr::Proto(name) => proto_matches(pkt, name),
            Expr::Cmp(field, op, value) => eval_cmp(pkt, *field, *op, value),
        }
    }
}

/// Match a bare protocol predicate against a packet. Transport names (`tcp`,
/// `udp`, `icmp`, `arp`) match by transport class, so `tcp` also matches HTTP
/// and TLS — as in Wireshark. Everything else matches the protocol's own name.
fn proto_matches(pkt: &Packet, name: &str) -> bool {
    let transport = Transport::from_protocol(&pkt.protocol);
    match name {
        "ip" => pkt.src_addr.is_some() || pkt.dst_addr.is_some(),
        "ipv4" => is_v4(pkt.src_addr) || is_v4(pkt.dst_addr),
        "ipv6" => is_v6(pkt.src_addr) || is_v6(pkt.dst_addr),
        "tcp" => transport == Transport::Tcp,
        "udp" => transport == Transport::Udp,
        "icmp" => transport == Transport::Icmp,
        "arp" => transport == Transport::Arp,
        "wlan" | "wifi" => pkt.protocol.to_string() == "802.11",
        // Hardware-bus captures: display names differ from the bare tokens.
        "usb" => pkt.protocol == Protocol::Usb,
        "bluetooth" | "hci" => pkt.protocol == Protocol::Bluetooth,
        "can" => pkt.protocol == Protocol::Can,
        "ws" => pkt.protocol == Protocol::WebSocket,
        // Display is "HTTP/2", which the lexer can't produce as a bare word.
        "http2" => pkt.protocol == Protocol::Http2,
        // Short aliases for protocols whose display name is longer/branded.
        "postgres" | "psql" | "pgsql" => pkt.protocol == Protocol::Postgres,
        "mongo" => pkt.protocol == Protocol::Mongodb,
        // Display is "VNC/RFB", which the lexer can't produce as a bare word.
        "rfb" | "vnc" => pkt.protocol == Protocol::Rfb,
        // Display names carry a "+" or hyphen the fallback can't match verbatim.
        "tacacs" | "tacacs+" => pkt.protocol == Protocol::Tacacs,
        "ipmi" => pkt.protocol == Protocol::Rmcp,
        "wsd" | "wsdiscovery" => pkt.protocol == Protocol::WsDiscovery,
        "ipfix" => pkt.protocol == Protocol::Netflow,
        "wol" | "wakeonlan" => pkt.protocol == Protocol::Wol,
        "nbds" => pkt.protocol == Protocol::Nbds,
        "iec104" => pkt.protocol == Protocol::Iec104,
        "ike" => pkt.protocol == Protocol::Isakmp,
        "nfs" | "portmap" => pkt.protocol == Protocol::Rpc,
        other => pkt.protocol.to_string().eq_ignore_ascii_case(other),
    }
}

fn is_v4(a: Option<IpAddr>) -> bool {
    matches!(a, Some(IpAddr::V4(_)))
}
fn is_v6(a: Option<IpAddr>) -> bool {
    matches!(a, Some(IpAddr::V6(_)))
}

fn eval_cmp(pkt: &Packet, field: Field, op: CmpOp, value: &Value) -> bool {
    match field {
        Field::IpAny => cmp_addr_any(pkt.src_addr, pkt.dst_addr, op, value),
        Field::IpSrc => cmp_addr_one(pkt.src_addr, op, value),
        Field::IpDst => cmp_addr_one(pkt.dst_addr, op, value),
        Field::PortAny => cmp_port_any(pkt, None, op, value),
        Field::TcpPort => cmp_port_any(pkt, Some(Transport::Tcp), op, value),
        Field::UdpPort => cmp_port_any(pkt, Some(Transport::Udp), op, value),
        Field::FrameLen => cmp_num(Some(pkt.length as u64), op, value),
        Field::TcpFlag(mask) => cmp_num(tcp_flag_value(pkt, mask), op, value),
        Field::HttpMethod => cmp_text(
            http_request_parts(pkt).map(|(m, _)| m).as_deref(),
            op,
            value,
        ),
        Field::HttpUri => cmp_text(
            http_request_parts(pkt).map(|(_, u)| u).as_deref(),
            op,
            value,
        ),
        Field::HttpHost => cmp_text(http_host(pkt).as_deref(), op, value),
        Field::HttpRespCode => cmp_num(http_response_code(pkt), op, value),
        Field::DnsQryName => cmp_text(dns_qry_name(pkt).as_deref(), op, value),
        Field::TlsJa3 => cmp_text(tls_ja3(pkt).as_deref(), op, value),
        Field::TlsJa4 => cmp_text(tls_ja4(pkt).as_deref(), op, value),
        Field::TlsJa3s => cmp_text(tls_ja3s(pkt).as_deref(), op, value),
        Field::Info => cmp_text(Some(&pkt.summary), op, value),
        Field::RtpSsrc => cmp_num(rtp_ssrc(pkt), op, value),
        Field::RtpSeq => cmp_num(rtp_seq(pkt), op, value),
        Field::NtlmUser => cmp_text(ntlm_field(&pkt.summary, "User: ").as_deref(), op, value),
        Field::NtlmDomain => cmp_text(ntlm_field(&pkt.summary, "Domain: ").as_deref(), op, value),
        Field::NtlmWorkstation => cmp_text(
            ntlm_field(&pkt.summary, "Workstation: ").as_deref(),
            op,
            value,
        ),
        Field::TlsSni => cmp_text(tls_sni(pkt).as_deref(), op, value),
        Field::Http3Method => cmp_text(ntlm_field(&pkt.summary, ":method: ").as_deref(), op, value),
        Field::Http3Status => {
            let s = ntlm_field(&pkt.summary, ":status: ");
            let val = s.and_then(|x| x.parse::<u64>().ok());
            cmp_num(val, op, value)
        }
    }
}

// ---- Frame-derived fields ------------------------------------------------
//
// These fields read the captured frame bytes ([`Packet::data`]) directly:
// Ethernet (+ optional VLAN tags) → IPv4/IPv6 → TCP/UDP → payload. Packets
// whose bytes don't reach the requested layer simply don't have the field,
// and any comparison on a missing field is false — same as Wireshark.

struct FrameMeta<'a> {
    ip_proto: u8,
    tcp_flags: Option<u8>,
    payload: &'a [u8],
}

fn frame_meta(data: &[u8]) -> Option<FrameMeta<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([data[off], data[off + 1]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        off += 4;
        ethertype = u16::from_be_bytes([*data.get(off)?, *data.get(off + 1)?]);
    }
    let l3 = off + 2;
    let (ip_proto, l4) = match ethertype {
        0x0800 => {
            let ihl = ((*data.get(l3)? & 0x0f) as usize) * 4;
            if ihl < 20 {
                return None;
            }
            (*data.get(l3 + 9)?, l3 + ihl)
        }
        // IPv6 fixed header only; extension headers are not walked.
        0x86dd => (*data.get(l3 + 6)?, l3 + 40),
        _ => return None,
    };
    match ip_proto {
        6 => {
            let doff = ((*data.get(l4 + 12)? >> 4) as usize) * 4;
            if doff < 20 {
                return None;
            }
            Some(FrameMeta {
                ip_proto,
                tcp_flags: Some(*data.get(l4 + 13)?),
                payload: data.get(l4 + doff..).unwrap_or(&[]),
            })
        }
        17 => Some(FrameMeta {
            ip_proto,
            tcp_flags: None,
            payload: data.get(l4 + 8..).unwrap_or(&[]),
        }),
        _ => Some(FrameMeta {
            ip_proto,
            tcp_flags: None,
            payload: &[],
        }),
    }
}

fn tcp_flag_value(pkt: &Packet, mask: u8) -> Option<u64> {
    let flags = frame_meta(&pkt.data)?.tcp_flags?;
    Some(u64::from(flags & mask != 0))
}

const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// First ~2 KiB of the TCP payload as text — enough for any request/status
/// line and headers without copying large bodies around. Borrows straight
/// from the frame bytes when they're valid UTF-8 (the common case), so a
/// filter evaluation allocates nothing here (ROADMAP §4.2).
fn http_head(pkt: &Packet) -> Option<std::borrow::Cow<'_, str>> {
    let m = frame_meta(&pkt.data)?;
    if m.ip_proto != 6 || m.payload.is_empty() {
        return None;
    }
    let head = &m.payload[..m.payload.len().min(2048)];
    Some(String::from_utf8_lossy(head))
}

/// `(method, uri)` when the payload starts with an HTTP request line.
fn http_request_parts(pkt: &Packet) -> Option<(String, String)> {
    let head = http_head(pkt)?;
    let line = head.lines().next()?;
    let mut it = line.split_whitespace();
    let method = it.next()?;
    let uri = it.next()?;
    if !it.next()?.starts_with("HTTP/") || !HTTP_METHODS.contains(&method) {
        return None;
    }
    Some((method.to_string(), uri.to_string()))
}

fn http_response_code(pkt: &Packet) -> Option<u64> {
    let head = http_head(pkt)?;
    let line = head.lines().next()?;
    let mut it = line.split_whitespace();
    if !it.next()?.starts_with("HTTP/") {
        return None;
    }
    it.next()?.parse().ok()
}

fn http_host(pkt: &Packet) -> Option<String> {
    http_request_parts(pkt)?; // Host is a request-side field
    let head = http_head(pkt)?;
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break; // blank line ends the headers
        }
        if let Some((name, val)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

/// The TLS record payload of a TCP packet dissected as TLS, for fingerprinting.
fn tls_payload(pkt: &Packet) -> Option<&[u8]> {
    if pkt.protocol != Protocol::Tls {
        return None;
    }
    let m = frame_meta(&pkt.data)?;
    if m.ip_proto != 6 {
        return None;
    }
    Some(m.payload)
}

/// JA3 client fingerprint of a TLS ClientHello, recomputed from frame bytes.
fn tls_ja3(pkt: &Packet) -> Option<String> {
    use crate::dissectors::tls;
    let h = tls::parse_client_hello(tls_payload(pkt)?)?;
    Some(tls::ja3_hash(&h))
}

/// JA4 client fingerprint of a TLS ClientHello (TCP transport).
fn tls_ja4(pkt: &Packet) -> Option<String> {
    use crate::dissectors::tls;
    let h = tls::parse_client_hello(tls_payload(pkt)?)?;
    Some(tls::ja4(&h, 't'))
}

/// JA3S server fingerprint of a TLS ServerHello.
fn tls_ja3s(pkt: &Packet) -> Option<String> {
    use crate::dissectors::tls;
    let s = tls::parse_server_hello(tls_payload(pkt)?)?;
    Some(tls::ja3s_hash(&s))
}

fn tls_sni(pkt: &Packet) -> Option<String> {
    use crate::dissectors::tls;
    let h = tls::parse_client_hello(tls_payload(pkt)?)?;
    h.sni
}

fn rtp_ssrc(pkt: &Packet) -> Option<u64> {
    let s = &pkt.summary;
    let idx = s.find("SSRC 0x")?;
    let rest = &s[idx + 7..];
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    u64::from_str_radix(&rest[..end], 16).ok()
}

fn rtp_seq(pkt: &Packet) -> Option<u64> {
    let s = &pkt.summary;
    let idx = s.find("seq ")?;
    let rest = &s[idx + 4..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn ntlm_field(summary: &str, prefix: &str) -> Option<String> {
    let idx = summary.find(prefix)?;
    let rest = &summary[idx + prefix.len()..];
    let end = rest.find([',', ')']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

/// First question name of a DNS/mDNS message, dotted (`example.com`).
pub fn dns_qry_name(pkt: &Packet) -> Option<String> {
    if !matches!(pkt.protocol, Protocol::Dns | Protocol::Mdns) {
        return None;
    }
    let m = frame_meta(&pkt.data)?;
    if m.ip_proto != 17 {
        return None;
    }
    parse_dns_qname(m.payload)
}

fn parse_dns_qname(p: &[u8]) -> Option<String> {
    let qdcount = u16::from_be_bytes([*p.get(4)?, *p.get(5)?]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut out = String::new();
    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer — QNAMEs in questions are literal
        }
        i += 1;
        let label = p.get(i..i + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        i += len;
        if out.len() > 255 {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Case-insensitive text comparison for protocol string fields. Equality
/// compares in place; only `contains` needs lowercased copies.
fn cmp_text(field: Option<&str>, op: CmpOp, value: &Value) -> bool {
    let Some(field) = field else { return false };
    let target = value_text(value);
    match op {
        CmpOp::Eq => field.eq_ignore_ascii_case(&target),
        CmpOp::Ne => !field.eq_ignore_ascii_case(&target),
        CmpOp::Contains => field
            .to_ascii_lowercase()
            .contains(&target.to_ascii_lowercase()),
        _ => false, // ordering on text is undefined
    }
}

fn value_ip(value: &Value) -> Option<IpAddr> {
    match value {
        Value::Ip(ip) => Some(*ip),
        Value::Text(t) => t.parse().ok(),
        Value::Num(_) => None,
    }
}

fn cmp_addr_one(addr: Option<IpAddr>, op: CmpOp, value: &Value) -> bool {
    let Some(addr) = addr else { return false };
    if op == CmpOp::Contains {
        return addr.to_string().contains(value_text(value).as_ref());
    }
    let Some(target) = value_ip(value) else {
        return false;
    };
    match op {
        CmpOp::Eq => addr == target,
        CmpOp::Ne => addr != target,
        _ => false, // ordering on addresses is undefined
    }
}

fn cmp_addr_any(src: Option<IpAddr>, dst: Option<IpAddr>, op: CmpOp, value: &Value) -> bool {
    match op {
        // `ip.addr != x` means neither endpoint is x.
        CmpOp::Ne => cmp_addr_one(src, CmpOp::Ne, value) && cmp_addr_one(dst, CmpOp::Ne, value),
        _ => cmp_addr_one(src, op, value) || cmp_addr_one(dst, op, value),
    }
}

fn cmp_port_any(pkt: &Packet, want: Option<Transport>, op: CmpOp, value: &Value) -> bool {
    if let Some(t) = want {
        if Transport::from_protocol(&pkt.protocol) != t {
            return false;
        }
    }
    let src = pkt.src_port.map(|p| p as u64);
    let dst = pkt.dst_port.map(|p| p as u64);
    match op {
        // `tcp.port != x` means neither side is x.
        CmpOp::Ne => cmp_num(src, CmpOp::Ne, value) && cmp_num(dst, CmpOp::Ne, value),
        _ => cmp_num(src, op, value) || cmp_num(dst, op, value),
    }
}

fn cmp_num(field: Option<u64>, op: CmpOp, value: &Value) -> bool {
    let Some(field) = field else { return false };
    if op == CmpOp::Contains {
        return field.to_string().contains(value_text(value).as_ref());
    }
    let Value::Num(v) = value else { return false };
    match op {
        CmpOp::Eq => field == *v,
        CmpOp::Ne => field != *v,
        CmpOp::Gt => field > *v,
        CmpOp::Lt => field < *v,
        CmpOp::Ge => field >= *v,
        CmpOp::Le => field <= *v,
        CmpOp::Contains => unreachable!(),
    }
}

fn value_text(value: &Value) -> std::borrow::Cow<'_, str> {
    match value {
        Value::Num(n) => n.to_string().into(),
        Value::Ip(ip) => ip.to_string().into(),
        Value::Text(t) => t.as_str().into(),
    }
}

// ---- Lexer --------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Cmp(CmpOp),
    Word(String),
    Str(String),
    Num(u64),
    Ip(IpAddr),
}

fn lex(input: &str) -> Result<Vec<Tok>, FilterError> {
    let bytes = input.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            b'&' => {
                i += if bytes.get(i + 1) == Some(&b'&') {
                    2
                } else {
                    1
                };
                toks.push(Tok::And);
            }
            b'|' => {
                i += if bytes.get(i + 1) == Some(&b'|') {
                    2
                } else {
                    1
                };
                toks.push(Tok::Or);
            }
            b'=' => {
                i += if bytes.get(i + 1) == Some(&b'=') {
                    2
                } else {
                    1
                };
                toks.push(Tok::Cmp(CmpOp::Eq));
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push(Tok::Cmp(CmpOp::Ne));
                    i += 2;
                } else {
                    toks.push(Tok::Not);
                    i += 1;
                }
            }
            b'>' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push(Tok::Cmp(CmpOp::Ge));
                    i += 2;
                } else {
                    toks.push(Tok::Cmp(CmpOp::Gt));
                    i += 1;
                }
            }
            b'<' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    toks.push(Tok::Cmp(CmpOp::Le));
                    i += 2;
                } else {
                    toks.push(Tok::Cmp(CmpOp::Lt));
                    i += 1;
                }
            }
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                if j >= bytes.len() {
                    return Err(FilterError("unterminated string".into()));
                }
                toks.push(Tok::Str(input[start..j].to_string()));
                i = j + 1;
            }
            _ if is_word_byte(c) => {
                let start = i;
                while i < bytes.len() && is_word_byte(bytes[i]) {
                    i += 1;
                }
                let word = &input[start..i];
                toks.push(classify_word(word));
            }
            other => {
                return Err(FilterError(format!(
                    "unexpected character '{}'",
                    other as char
                )));
            }
        }
    }
    Ok(toks)
}

/// Bytes allowed inside an unquoted token: identifiers (`ip.src`), numbers,
/// IPv4/IPv6 addresses (hence `.` and `:`), and hostnames (hence `-`).
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b':')
}

fn classify_word(word: &str) -> Tok {
    match word.to_ascii_lowercase().as_str() {
        "and" => Tok::And,
        "or" => Tok::Or,
        "not" => Tok::Not,
        "contains" => Tok::Cmp(CmpOp::Contains),
        _ => {
            if let Ok(ip) = word.parse::<IpAddr>() {
                Tok::Ip(ip)
            } else if word.starts_with("0x") || word.starts_with("0X") {
                if let Ok(n) = u64::from_str_radix(&word[2..], 16) {
                    Tok::Num(n)
                } else {
                    Tok::Word(word.to_string())
                }
            } else if let Ok(n) = word.parse::<u64>() {
                Tok::Num(n)
            } else {
                Tok::Word(word.to_string())
            }
        }
    }
}

// ---- Parser -------------------------------------------------------------

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.pos += 1;
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, FilterError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        match self.next() {
            Some(Tok::LParen) => {
                let inner = self.parse_or()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err(FilterError("expected ')'".into())),
                }
            }
            Some(Tok::Word(word)) => self.parse_word(word),
            Some(other) => Err(FilterError(format!("unexpected token {other:?}"))),
            None => Err(FilterError("unexpected end of filter".into())),
        }
    }

    /// A word is either a field (followed by a comparison + value) or a bare
    /// protocol predicate.
    fn parse_word(&mut self, word: String) -> Result<Expr, FilterError> {
        if let Some(Tok::Cmp(op)) = self.peek().cloned() {
            let field = field_from_word(&word)
                .ok_or_else(|| FilterError(format!("unknown field '{word}'")))?;
            self.pos += 1; // consume operator
            let value = self.parse_value()?;
            return Ok(Expr::Cmp(field, op, value));
        }
        // Bare predicate — must be a known protocol, else fall back to substring.
        let lower = word.to_ascii_lowercase();
        if KNOWN_PROTOS.contains(&lower.as_str()) {
            Ok(Expr::Proto(lower))
        } else {
            Err(FilterError(format!("unknown protocol '{word}'")))
        }
    }

    fn parse_value(&mut self) -> Result<Value, FilterError> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(Value::Num(n)),
            Some(Tok::Ip(ip)) => Ok(Value::Ip(ip)),
            Some(Tok::Str(s)) => Ok(Value::Text(s)),
            Some(Tok::Word(w)) => Ok(Value::Text(w)),
            _ => Err(FilterError("expected a value after operator".into())),
        }
    }
}

fn field_from_word(word: &str) -> Option<Field> {
    match word.to_ascii_lowercase().as_str() {
        "ip.addr" | "ip.address" => Some(Field::IpAny),
        "ip.src" | "ip.srcaddr" => Some(Field::IpSrc),
        "ip.dst" | "ip.dstaddr" => Some(Field::IpDst),
        "port" => Some(Field::PortAny),
        "tcp.port" => Some(Field::TcpPort),
        "udp.port" => Some(Field::UdpPort),
        "frame.len" | "len" | "length" => Some(Field::FrameLen),
        "tcp.flags.syn" => Some(Field::TcpFlag(TCP_SYN)),
        "tcp.flags.ack" => Some(Field::TcpFlag(TCP_ACK)),
        "tcp.flags.fin" => Some(Field::TcpFlag(TCP_FIN)),
        "tcp.flags.rst" | "tcp.flags.reset" => Some(Field::TcpFlag(TCP_RST)),
        "tcp.flags.psh" | "tcp.flags.push" => Some(Field::TcpFlag(TCP_PSH)),
        "http.request.method" | "http.method" => Some(Field::HttpMethod),
        "http.request.uri" | "http.request.path" | "http.uri" | "http.path" => Some(Field::HttpUri),
        "http.host" => Some(Field::HttpHost),
        "http.response.code" | "http.response.status" | "http.status" => Some(Field::HttpRespCode),
        "dns.qry.name" | "dns.query.name" | "dns.name" => Some(Field::DnsQryName),
        "tls.ja3" | "ja3" => Some(Field::TlsJa3),
        "tls.ja4" | "ja4" => Some(Field::TlsJa4),
        "tls.ja3s" | "ja3s" => Some(Field::TlsJa3s),
        "info" | "frame.info" | "summary" => Some(Field::Info),
        "rtp.ssrc" | "rtcp.ssrc" => Some(Field::RtpSsrc),
        "rtp.seq" | "rtp.sequence" => Some(Field::RtpSeq),
        "ntlm.user" | "ntlm.username" => Some(Field::NtlmUser),
        "ntlm.domain" => Some(Field::NtlmDomain),
        "ntlm.workstation" | "ntlm.host" => Some(Field::NtlmWorkstation),
        "tls.sni" | "tls.host" | "tls.server_name" => Some(Field::TlsSni),
        "http3.method" | "qpack.method" => Some(Field::Http3Method),
        "http3.status" | "qpack.status" => Some(Field::Http3Status),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use chrono::Utc;

    fn pkt(
        proto: Protocol,
        src: &str,
        dst: &str,
        sport: Option<u16>,
        dport: Option<u16>,
        len: usize,
        summary: &str,
    ) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: src.parse().ok(),
            dst_addr: dst.parse().ok(),
            src_port: sport,
            dst_port: dport,
            protocol: proto,
            length: len,
            summary: summary.into(),
            data: bytes::Bytes::new(),
        }
    }

    fn tcp443() -> Packet {
        pkt(
            Protocol::Tls,
            "192.168.1.5",
            "142.250.74.46",
            Some(51000),
            Some(443),
            1200,
            "TLS — google.com (HTTPS)",
        )
    }

    fn dns() -> Packet {
        pkt(
            Protocol::Dns,
            "192.168.1.5",
            "8.8.8.8",
            Some(51001),
            Some(53),
            80,
            "DNS Query — example.com",
        )
    }

    fn matches(expr: &str, p: &Packet) -> bool {
        Filter::parse(expr).unwrap().matches(p)
    }

    #[test]
    fn bare_protocol_predicate() {
        assert!(matches("tls", &tcp443()));
        assert!(matches("tcp", &tcp443())); // tcp matches TLS by transport
        assert!(!matches("udp", &tcp443()));
        assert!(matches("dns", &dns()));
        assert!(matches("udp", &dns()));
    }

    #[test]
    fn ip_addr_any_and_sides() {
        let p = tcp443();
        assert!(matches("ip.addr == 142.250.74.46", &p));
        assert!(matches("ip.addr == 192.168.1.5", &p));
        assert!(matches("ip.dst == 142.250.74.46", &p));
        assert!(!matches("ip.src == 142.250.74.46", &p));
        assert!(matches("ip.addr != 10.0.0.1", &p));
        assert!(!matches("ip.addr != 142.250.74.46", &p));
    }

    #[test]
    fn port_fields() {
        let p = tcp443();
        assert!(matches("port == 443", &p));
        assert!(matches("tcp.port == 443", &p));
        assert!(!matches("udp.port == 443", &p)); // wrong transport
        assert!(matches("tcp.port != 80", &p));
        assert!(matches("port == 51000", &p));
    }

    #[test]
    fn frame_len_ordering() {
        let p = tcp443();
        assert!(matches("frame.len > 1000", &p));
        assert!(matches("len >= 1200", &p));
        assert!(!matches("frame.len < 500", &p));
        assert!(matches("length <= 1200", &p));
    }

    #[test]
    fn boolean_logic_and_precedence() {
        let p = tcp443();
        assert!(matches("tcp && tcp.port == 443", &p));
        assert!(matches("udp || tls", &p));
        assert!(matches("dns or ip.dst == 142.250.74.46", &p));
        assert!(!matches("tcp && udp", &p));
        assert!(matches("!udp", &p));
        assert!(matches("not udp", &p));
        // && binds tighter than ||: (udp && arp) is false, but tls is true.
        assert!(matches("udp && arp || tls", &p));
    }

    #[test]
    fn parentheses_group() {
        let p = tcp443();
        assert!(!matches("udp && (tls || dns)", &p));
        assert!(matches("tcp && (tls || dns)", &p));
    }

    #[test]
    fn contains_operator() {
        let p = tcp443();
        assert!(matches("ip.dst contains \"142.250\"", &p));
        assert!(!matches("ip.src contains \"999\"", &p));
    }

    #[test]
    fn invalid_syntax_is_error_for_fallback() {
        // Free text a user might type — must NOT parse, so the UI substring
        // fallback kicks in.
        assert!(Filter::parse("google").is_err());
        assert!(Filter::parse("").is_err());
        assert!(Filter::parse("ip.addr ==").is_err());
        assert!(Filter::parse("tcp.port == ").is_err());
        assert!(Filter::parse("(tcp").is_err());
        assert!(Filter::parse("unknownfield == 5").is_err());
        assert!(Filter::parse("tcp &&").is_err());
    }

    // ---- Raw-frame builders for the protocol-field tests ----

    /// Ethernet + IPv4 + TCP frame with the given flags byte and payload.
    fn tcp_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08; // EtherType IPv4
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, IHL 5
        ip[9] = 6; // TCP
        let mut tcp = vec![0u8; 20];
        tcp[12] = 0x50; // data offset 5
        tcp[13] = flags;
        f.extend(ip);
        f.extend(tcp);
        f.extend(payload);
        f
    }

    /// Ethernet + IPv4 + UDP frame with the given payload.
    fn udp_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 17; // UDP
        f.extend(ip);
        f.extend(vec![0u8; 8]); // UDP header
        f.extend(payload);
        f
    }

    /// A DNS message with one question for the given dotted name.
    fn dns_question(name: &str) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[5] = 1; // QDCOUNT = 1
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend(label.as_bytes());
        }
        m.push(0);
        m.extend([0, 1, 0, 1]); // QTYPE A, QCLASS IN
        m
    }

    fn with_data(mut p: Packet, data: Vec<u8>) -> Packet {
        p.data = data.into();
        p
    }

    #[test]
    fn tcp_flag_fields() {
        let syn = with_data(tcp443(), tcp_frame(0x02, &[]));
        assert!(matches("tcp.flags.syn == 1", &syn));
        assert!(matches("tcp.flags.ack == 0", &syn));
        assert!(!matches("tcp.flags.rst == 1", &syn));

        let rst_ack = with_data(tcp443(), tcp_frame(0x14, &[]));
        assert!(matches(
            "tcp.flags.rst == 1 && tcp.flags.ack == 1",
            &rst_ack
        ));
        assert!(!matches("tcp.flags.syn == 1", &rst_ack));

        // A UDP packet has no TCP flags — every comparison is false.
        let udp = with_data(dns(), udp_frame(&[]));
        assert!(!matches("tcp.flags.syn == 1", &udp));
        assert!(!matches("tcp.flags.syn == 0", &udp));
    }

    #[test]
    fn http_request_fields() {
        let req = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\n\r\nhi";
        let p = with_data(
            pkt(
                Protocol::Http,
                "10.0.0.1",
                "10.0.0.2",
                Some(50000),
                Some(80),
                200,
                "HTTP POST",
            ),
            tcp_frame(0x18, req),
        );
        assert!(matches("http.request.method == \"POST\"", &p));
        assert!(matches("http.request.method == post", &p)); // case-insensitive
        assert!(!matches("http.request.method == GET", &p));
        assert!(matches("http.request.uri contains \"/api\"", &p));
        assert!(matches("http.host == example.com", &p));
        assert!(!matches("http.response.code == 200", &p)); // it's a request
    }

    #[test]
    fn http_response_code_field() {
        let resp = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n";
        let p = with_data(
            pkt(
                Protocol::Http,
                "10.0.0.2",
                "10.0.0.1",
                Some(80),
                Some(50000),
                120,
                "HTTP 404",
            ),
            tcp_frame(0x18, resp),
        );
        assert!(matches("http.response.code == 404", &p));
        assert!(matches("http.response.code >= 400", &p));
        assert!(!matches("http.request.method == GET", &p)); // it's a response
    }

    #[test]
    fn dns_query_name_field() {
        let p = with_data(dns(), udp_frame(&dns_question("example.com")));
        assert!(matches("dns.qry.name == example.com", &p));
        assert!(matches("dns.qry.name contains \"example\"", &p));
        assert!(!matches("dns.qry.name == other.org", &p));
        // Non-DNS packets never match the field.
        let t = with_data(tcp443(), tcp_frame(0x10, &[]));
        assert!(!matches("dns.qry.name contains \"example\"", &t));
    }

    /// A minimal TLS ClientHello record: one cipher (0x002f), no extensions.
    fn client_hello_record() -> Vec<u8> {
        let mut body = vec![0x03, 0x03]; // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session id length
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0
        let mut hs = vec![0x01]; // ClientHello
        hs.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A minimal TLS ServerHello record: chosen cipher 0x002f, no extensions.
    fn server_hello_record() -> Vec<u8> {
        let mut body = vec![0x03, 0x03]; // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session id length
        body.extend_from_slice(&[0x00, 0x2f]); // chosen cipher
        body.push(0x00); // compression method
        body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0
        let mut hs = vec![0x02]; // ServerHello
        hs.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_fingerprint_fields() {
        use crate::dissectors::tls;
        let hello = client_hello_record();
        let p = with_data(tcp443(), tcp_frame(0x18, &hello));

        // The filter's ja3/ja4 must match the fingerprints recomputed directly.
        let h = tls::parse_client_hello(&hello).unwrap();
        let ja3 = tls::ja3_hash(&h);
        let ja4 = tls::ja4(&h, 't');
        assert!(matches(&format!("ja3 == {ja3}"), &p));
        assert!(matches(&format!("tls.ja3 == {ja3}"), &p));
        assert!(matches(&format!("ja4 == {ja4}"), &p));
        assert!(matches("ja3 != 00000000000000000000000000000000", &p));
        assert!(!matches("ja3 == deadbeefdeadbeefdeadbeefdeadbeef", &p));
        // A ClientHello has no JA3S.
        assert!(!matches("ja3s contains \"a\"", &p));

        // ServerHello: JA3S resolves, JA3/JA4 do not.
        let srv = server_hello_record();
        let s = with_data(tcp443(), tcp_frame(0x18, &srv));
        let ja3s = tls::ja3s_hash(&tls::parse_server_hello(&srv).unwrap());
        assert!(matches(&format!("ja3s == {ja3s}"), &s));
        assert!(!matches("ja3 contains \"a\"", &s));

        // Non-TLS packets never match a fingerprint field.
        let d = with_data(dns(), udp_frame(&dns_question("example.com")));
        assert!(!matches(&format!("ja3 == {ja3}"), &d));
    }

    #[test]
    fn websocket_predicate_and_alias() {
        let p = pkt(
            Protocol::WebSocket,
            "10.0.0.1",
            "10.0.0.2",
            Some(50000),
            Some(8080),
            64,
            "WebSocket Text — \"hi\"",
        );
        assert!(matches("websocket", &p));
        assert!(matches("ws", &p));
        assert!(matches("tcp", &p)); // rides on TCP
        assert!(!matches("websocket", &tcp443()));
        assert!(!matches("ws", &dns()));
    }

    #[test]
    fn http2_and_grpc_predicates() {
        let h2 = pkt(
            Protocol::Http2,
            "10.0.0.1",
            "10.0.0.2",
            Some(50000),
            Some(8080),
            64,
            "HTTP/2 SETTINGS — 2 parameters",
        );
        assert!(matches("http2", &h2));
        assert!(matches("tcp", &h2)); // rides on TCP
        assert!(!matches("http", &h2)); // HTTP/1.x is a different predicate
        assert!(!matches("grpc", &h2));

        let g = pkt(
            Protocol::Grpc,
            "10.0.0.1",
            "10.0.0.2",
            Some(50000),
            Some(50051),
            120,
            "gRPC message — 42 bytes (uncompressed) on stream 1",
        );
        assert!(matches("grpc", &g));
        assert!(matches("tcp", &g));
        assert!(!matches("http2", &g)); // labelled by the more specific protocol
    }

    #[test]
    fn info_field_over_summary() {
        let p = tcp443(); // summary: "TLS — google.com (HTTPS)"
        assert!(matches("info contains google", &p));
        assert!(matches("info contains \"HTTPS\"", &p));
        assert!(!matches("info contains yahoo", &p));
    }

    #[test]
    fn ipv6_addresses() {
        let p = pkt(
            Protocol::Tcp,
            "2606:4700::1",
            "2001:db8::5",
            Some(40000),
            Some(443),
            100,
            "TCP",
        );
        assert!(matches("ip.addr == 2606:4700::1", &p));
        assert!(matches("ipv6", &p));
        assert!(!matches("ipv4", &p));
    }

    #[test]
    fn test_new_filter_fields() {
        let rtp_pkt = pkt(
            Protocol::Rtp,
            "10.0.0.1",
            "10.0.0.2",
            Some(40000),
            Some(40002),
            200,
            "RTP PCMU/8000 — seq 1234, SSRC 0xdeadbeef, Jitter 1.2ms, MOS 4.2",
        );
        assert!(matches("rtp.ssrc == 0xdeadbeef", &rtp_pkt));
        assert!(matches("rtp.seq == 1234", &rtp_pkt));

        let ntlm_pkt = pkt(
            Protocol::Ntlm,
            "10.0.0.1",
            "10.0.0.2",
            Some(50000),
            Some(139),
            300,
            "NTLM Authenticate — User: administrator, Domain: WORK, Workstation: PC",
        );
        assert!(matches("ntlm.user == administrator", &ntlm_pkt));
        assert!(matches("ntlm.domain == WORK", &ntlm_pkt));
        assert!(matches("ntlm.workstation == PC", &ntlm_pkt));

        let quic_pkt = pkt(
            Protocol::Quic,
            "10.0.0.1",
            "10.0.0.2",
            Some(50000),
            Some(443),
            500,
            "QUIC — 1-RTT (HTTP/3 :method: GET, :status: 200), 500 bytes",
        );
        assert!(matches("http3.method == GET", &quic_pkt));
        assert!(matches("http3.status == 200", &quic_pkt));
    }
}
