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
//!   `wlan` / `wifi` / `802.11`.
//! - **Fields**: `ip.addr`, `ip.src`, `ip.dst`, `port`, `tcp.port`,
//!   `udp.port`, `frame.len` (aliases: `len`, `length`).
//! - **Comparisons**: `==` `!=` `>` `<` `>=` `<=`, plus `contains` (substring
//!   over the field's text form).
//! - **Logic**: `&&`/`and`, `||`/`or`, `!`/`not`, and parentheses.

use std::net::IpAddr;

use crate::flows::Transport;
use crate::models::Packet;

/// Protocol tokens accepted as bare predicates (e.g. `tcp`, `dns`).
const KNOWN_PROTOS: &[&str] = &[
    "ip", "ipv4", "ipv6", "tcp", "udp", "icmp", "arp", "dns", "http", "tls", "dhcp", "ntp", "mdns",
    "snmp", "quic", "sip", "ssh", "ftp", "smtp", "imap", "pop3", "telnet", "rdp", "wlan", "wifi",
    "802.11",
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
}

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
        return addr.to_string().contains(&value_text(value));
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
        return field.to_string().contains(&value_text(value));
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

fn value_text(value: &Value) -> String {
    match value {
        Value::Num(n) => n.to_string(),
        Value::Ip(ip) => ip.to_string(),
        Value::Text(t) => t.clone(),
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
            data: Vec::new(),
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
}
