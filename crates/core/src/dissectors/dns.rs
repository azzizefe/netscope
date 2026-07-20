// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

pub fn dissect_dns(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let parsed = dns_parser::Packet::parse(payload);

    match parsed {
        Ok(pkt) => {
            let is_query = pkt.header.query;
            let domain = pkt
                .questions
                .first()
                .map(|q| q.qname.to_string())
                .unwrap_or_default();

            let answers: Vec<String> = pkt
                .answers
                .iter()
                .filter_map(|a| {
                    if let dns_parser::RData::A(ip) = a.data {
                        Some(ip.0.to_string())
                    } else if let dns_parser::RData::AAAA(ip) = a.data {
                        Some(ip.0.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            let summary = if is_query {
                match pkt.questions.len() {
                    0 | 1 => format!("DNS Query — {domain}"),
                    n => format!("DNS Query — {domain} (+{} more)", n - 1),
                }
            } else if let Some(reason) = extended_error(payload).or_else(|| failure_reason(&pkt)) {
                // A lookup that failed is not a lookup that returned nothing.
                // "No answers" covered a name that does not exist, a resolver
                // that broke, and a resolver that refused on policy — three
                // different problems with three different fixes.
                format!("DNS Response — {domain} — {reason}")
            } else if !answers.is_empty() {
                format!("DNS Response — {} → {}", domain, answers.join(", "))
            } else if pkt.answers.is_empty() {
                format!("DNS Response — {domain} (no answers)")
            } else {
                let n = pkt.answers.len();
                let plural = if n == 1 { "record" } else { "records" };
                format!("DNS Response — {domain} ({n} {plural})")
            };

            DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                protocol: Protocol::Dns,
                summary,
            }
        }
        Err(_) => DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Unknown("unparsed DNS".into()),
            summary: "DNS — malformed packet".into(),
        },
    }
}

/// Why a lookup failed, or nothing when it did not.
///
/// The response code is four bits in the header, but EDNS extends it with eight
/// more carried in the OPT record — so a resolver reporting a code above 15 has
/// its real answer split across two places, and reading only the header gives a
/// different code entirely.
fn failure_reason(pkt: &dns_parser::Packet) -> Option<String> {
    use dns_parser::ResponseCode;

    let base = match pkt.header.response_code {
        ResponseCode::NoError => 0u16,
        ResponseCode::FormatError => 1,
        ResponseCode::ServerFailure => 2,
        ResponseCode::NameError => 3,
        ResponseCode::NotImplemented => 4,
        ResponseCode::Refused => 5,
        ResponseCode::Reserved(code) => code as u16,
    };
    // The OPT record supplies the high eight bits.
    let extended = pkt.opt.as_ref().map(|o| o.extrcode).unwrap_or(0);
    let code = ((extended as u16) << 4) | base;
    if code == 0 {
        return None;
    }
    Some(match response_code_name(code) {
        Some(text) => format!("{text} (rcode {code})"),
        None => format!("rcode {code}"),
    })
}

/// The OPT pseudo-record's type.
const TYPE_OPT: u16 = 41;
/// The extended DNS error option (RFC 8914).
const OPTION_EXTENDED_ERROR: u16 = 15;

/// Step over a DNS name, returning where it ends.
///
/// A name is a run of length-prefixed labels ending in a zero, except that a
/// label whose top two bits are set is a pointer to earlier in the message and
/// ends the name in two bytes. Following the pointer is unnecessary here — only
/// the length matters — but failing to recognise it would run the walk off into
/// the middle of a record.
fn skip_name(payload: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *payload.get(at)?;
        if len & 0xC0 == 0xC0 {
            return Some(at + 2);
        }
        at += 1 + len as usize;
        if len == 0 {
            return Some(at);
        }
        // A name cannot be longer than the message that holds it.
        if at > payload.len() {
            return None;
        }
    }
}

/// Read the extended DNS error, which says what a resolver actually did.
///
/// The library this dissector otherwise uses does not parse OPT options, so the
/// record is located by walking the sections rather than by searching for its
/// bytes — the option code and an ordinary two-byte value are indistinguishable
/// on their own, and a search would find whichever came first.
fn extended_error(payload: &[u8]) -> Option<String> {
    let counts: Vec<u16> = (2..6)
        .map(|i| {
            u16::from_be_bytes([
                *payload.get(i * 2).unwrap_or(&0),
                *payload.get(i * 2 + 1).unwrap_or(&0),
            ])
        })
        .collect();
    let (questions, answers, authority, additional) = (counts[0], counts[1], counts[2], counts[3]);
    if additional == 0 {
        return None;
    }

    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(payload, at)? + 4;
    }
    for _ in 0..(answers as u32 + authority as u32) {
        at = skip_name(payload, at)?;
        let rdlength = u16::from_be_bytes([*payload.get(at + 8)?, *payload.get(at + 9)?]) as usize;
        at += 10 + rdlength;
    }

    for _ in 0..additional {
        let after_name = skip_name(payload, at)?;
        let rtype = u16::from_be_bytes([*payload.get(after_name)?, *payload.get(after_name + 1)?]);
        let rdlength =
            u16::from_be_bytes([*payload.get(after_name + 8)?, *payload.get(after_name + 9)?])
                as usize;
        let rdata_at = after_name + 10;
        if rtype == TYPE_OPT {
            return read_extended_error(payload.get(rdata_at..rdata_at + rdlength)?);
        }
        at = rdata_at + rdlength;
    }
    None
}

/// Walk the OPT record's options for the extended error.
fn read_extended_error(mut rdata: &[u8]) -> Option<String> {
    while rdata.len() >= 4 {
        let code = u16::from_be_bytes([rdata[0], rdata[1]]);
        let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
        let value = rdata.get(4..4 + len)?;
        if code == OPTION_EXTENDED_ERROR && value.len() >= 2 {
            let info = u16::from_be_bytes([value[0], value[1]]);
            // Anything after the code is free text the resolver chose to add.
            let extra = std::str::from_utf8(&value[2..])
                .ok()
                .map(str::trim)
                .filter(|t| !t.is_empty() && t.chars().all(|c| !c.is_control()));
            let name = extended_error_name(info)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("extended error {info}"));
            return Some(match extra {
                Some(text) => format!("{name} — {}", super::truncate(text, 40)),
                None => name,
            });
        }
        rdata = rdata.get(4 + len..)?;
    }
    None
}

/// What an extended DNS error means (RFC 8914).
///
/// These exist because the old response codes could not distinguish a name that
/// does not resolve from one a resolver was told not to resolve. That is the
/// difference between a broken domain and a blocked one.
fn extended_error_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0 => "other",
        1 => "unsupported DNSSEC algorithm",
        2 => "unsupported DNSSEC digest type",
        3 => "stale answer",
        4 => "forged answer",
        5 => "DNSSEC indeterminate",
        6 => "DNSSEC bogus (the signatures did not verify)",
        7 => "signature expired",
        8 => "signature not yet valid",
        9 => "no DNSKEY matching the DS record",
        10 => "no RRSIG matching the DNSKEY",
        11 => "no zone key bit set",
        12 => "NSEC record missing",
        13 => "cached error",
        14 => "not ready",
        15 => "blocked by the resolver's policy",
        16 => "censored upstream",
        17 => "filtered at the client's request",
        18 => "the client is not allowed to query this resolver",
        19 => "the upstream server returned an error",
        20 => "query type not supported",
        21 => "query refused outright",
        22 => "no reachable authority",
        23 => "network error reaching the authority",
        24 => "invalid data from the authority",
        _ => return None,
    })
}

/// What a DNS response code means.
fn response_code_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1 => "the query was malformed",
        2 => "the resolver failed (often a broken DNSSEC chain)",
        3 => "no such name (NXDOMAIN)",
        4 => "the resolver does not implement this query",
        5 => "refused by policy",
        6 => "the name exists when it should not",
        7 => "the record set exists when it should not",
        8 => "the record set does not exist",
        9 => "the server is not authoritative for this zone",
        10 => "the name is not in the zone",
        16 => "bad OPT version, or a signature outside its validity window",
        17 => "the key is not recognised",
        18 => "the signature is outside its time window",
        19 => "bad transaction key mode",
        20 => "duplicate key name",
        21 => "the algorithm is not supported",
        22 => "bad truncation",
        23 => "bad or missing server cookie",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{build_dns_query, build_dns_response};

    #[test]
    fn dns_query() {
        let payload = build_dns_query("google.com", 0x1234);
        let result = dissect_dns(None, None, 54321, 53, &payload);
        assert_eq!(result.protocol, Protocol::Dns);
        assert_eq!(result.summary, "DNS Query — google.com");
    }

    #[test]
    fn dns_response() {
        let payload = build_dns_response("google.com", 0x1234, [142, 250, 74, 46]);
        let result = dissect_dns(None, None, 53, 54321, &payload);
        assert_eq!(result.protocol, Protocol::Dns);
        assert!(result.summary.contains("google.com"));
        assert!(result.summary.contains("142.250.74.46"));
    }

    #[test]
    fn dns_malformed() {
        let result = dissect_dns(None, None, 53, 54321, &[0; 3]);
        assert_eq!(result.summary, "DNS — malformed packet");
    }

    #[test]
    fn dns_empty_payload() {
        let result = dissect_dns(None, None, 53, 54321, &[]);
        assert_eq!(result.summary, "DNS — malformed packet");
    }

    #[test]
    fn dns_aaaa_response() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // ID
        buf.extend_from_slice(&[0x81, 0x80]); // flags: response
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x01]); // answers: 1
        buf.extend_from_slice(&[0x00, 0x00]); // authority
        buf.extend_from_slice(&[0x00, 0x00]); // additional
                                              // Question: example.com
        buf.extend_from_slice(b"\x07example\x03com\x00");
        buf.extend_from_slice(&[0x00, 0x1c]); // type: AAAA
        buf.extend_from_slice(&[0x00, 0x01]); // class: IN
                                              // Answer
        buf.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        buf.extend_from_slice(&[0x00, 0x1c]); // type: AAAA
        buf.extend_from_slice(&[0x00, 0x01]); // class: IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
        buf.extend_from_slice(&[0x00, 0x10]); // data length: 16
        buf.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]); // 2001:db8::1

        let result = dissect_dns(None, None, 53, 54321, &buf);
        assert_eq!(result.protocol, Protocol::Dns);
        assert!(result.summary.contains("example.com"));
        assert!(result.summary.contains("2001:db8::1"));
    }

    /// A response with no answers and the given four-bit response code.
    fn failed_response(rcode: u8) -> Vec<u8> {
        let mut buf = vec![0x12, 0x34];
        // Response, recursion desired and available, then the code.
        buf.push(0x81);
        buf.push(0x80 | (rcode & 0x0F));
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x00]); // answers: 0
        buf.extend_from_slice(&[0x00, 0x00]); // authority: 0
        buf.extend_from_slice(&[0x00, 0x00]); // additional: 0
        buf.extend_from_slice(b"\x07missing\x07example\x03com\x00");
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        buf
    }

    /// The same response with an OPT record supplying the upper eight bits of
    /// the code, and an advertised UDP size.
    fn failed_response_with_opt(rcode: u8, extended: u8) -> Vec<u8> {
        let mut buf = failed_response(rcode);
        buf[11] = 0x01; // additional: 1
        buf.push(0x00); // OPT name: root
        buf.extend_from_slice(&[0x00, 0x29]); // type: OPT (41)
        buf.extend_from_slice(&[0x10, 0x00]); // class: 4096-byte UDP size
        buf.push(extended); // upper eight bits of the response code
        buf.push(0x00); // EDNS version
        buf.extend_from_slice(&[0x80, 0x00]); // flags: DNSSEC OK
        buf.extend_from_slice(&[0x00, 0x00]); // rdlength
        buf
    }

    /// The three commonest failures were one line before this: "no answers".
    /// They are completely different problems.
    #[test]
    fn a_failed_lookup_says_which_failure_it_was() {
        let r = dissect_dns(None, None, 53, 54321, &failed_response(3));
        assert_eq!(
            r.summary,
            "DNS Response — missing.example.com — no such name (NXDOMAIN) (rcode 3)"
        );
        assert!(dissect_dns(None, None, 53, 1, &failed_response(2))
            .summary
            .contains("the resolver failed"));
        assert!(dissect_dns(None, None, 53, 1, &failed_response(5))
            .summary
            .contains("refused by policy"));
    }

    /// A successful lookup must not be reported as a failure, and an empty but
    /// successful answer keeps its old wording.
    #[test]
    fn a_successful_response_is_not_called_a_failure() {
        let payload = build_dns_response("example.com", 0x1234, [93, 184, 216, 34]);
        let r = dissect_dns(None, None, 53, 54321, &payload);
        assert!(!r.summary.contains("rcode"), "{}", r.summary);

        let r = dissect_dns(None, None, 53, 1, &failed_response(0));
        assert_eq!(r.summary, "DNS Response — missing.example.com (no answers)");
    }

    /// The response code is four bits in the header plus eight more in the OPT
    /// record. Reading only the header turns code 16 into code 0 — a failure
    /// reported as a success.
    #[test]
    fn the_extended_response_code_is_assembled_from_both_halves() {
        // rcode 16 = extended 1, base 0.
        let r = dissect_dns(None, None, 53, 1, &failed_response_with_opt(0, 1));
        assert!(r.summary.contains("rcode 16"), "{}", r.summary);
        assert!(r.summary.contains("bad OPT version"), "{}", r.summary);

        // rcode 23 (bad cookie) = extended 1, base 7.
        let r = dissect_dns(None, None, 53, 1, &failed_response_with_opt(7, 1));
        assert!(r.summary.contains("rcode 23"), "{}", r.summary);
    }

    /// A code outside the table keeps its number rather than being mapped to
    /// whichever meaning was nearest.
    #[test]
    fn an_unknown_response_code_keeps_its_number() {
        let r = dissect_dns(None, None, 53, 1, &failed_response(11));
        assert_eq!(r.summary, "DNS Response — missing.example.com — rcode 11");
    }

    /// A failed response carrying an extended error option.
    fn response_with_extended_error(rcode: u8, info: u16, text: &str) -> Vec<u8> {
        let mut buf = failed_response(rcode);
        buf[11] = 0x01; // additional: 1

        let mut option = OPTION_EXTENDED_ERROR.to_be_bytes().to_vec();
        let mut value = info.to_be_bytes().to_vec();
        value.extend_from_slice(text.as_bytes());
        option.extend_from_slice(&(value.len() as u16).to_be_bytes());
        option.extend_from_slice(&value);

        buf.push(0x00); // OPT name: root
        buf.extend_from_slice(&TYPE_OPT.to_be_bytes());
        buf.extend_from_slice(&[0x10, 0x00]); // UDP size
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extended rcode, version, flags
        buf.extend_from_slice(&(option.len() as u16).to_be_bytes());
        buf.extend_from_slice(&option);
        buf
    }

    /// The reason these exist: the old response codes cannot tell a domain that
    /// does not resolve from one a resolver was told not to resolve. Both are
    /// SERVFAIL, and they are entirely different situations.
    #[test]
    fn a_blocked_domain_is_distinguished_from_a_broken_one() {
        let blocked = response_with_extended_error(5, 15, "");
        assert_eq!(
            dissect_dns(None, None, 53, 1, &blocked).summary,
            "DNS Response — missing.example.com — blocked by the resolver's policy"
        );
        let bogus = response_with_extended_error(2, 6, "");
        assert!(dissect_dns(None, None, 53, 1, &bogus)
            .summary
            .contains("the signatures did not verify"));
        assert!(
            dissect_dns(None, None, 53, 1, &response_with_extended_error(2, 16, ""))
                .summary
                .contains("censored upstream")
        );
    }

    /// A resolver may add its own explanation, which is the most direct answer
    /// available and travels in the clear.
    #[test]
    fn the_resolvers_own_explanation_is_shown() {
        let p = response_with_extended_error(5, 15, "blocked by parental controls");
        assert_eq!(
            dissect_dns(None, None, 53, 1, &p).summary,
            "DNS Response — missing.example.com — blocked by the resolver's policy \
— blocked by parental controls"
        );
    }

    /// The OPT record is found by walking the sections, not by searching for
    /// the option code — an ordinary two-byte value can equal it, and a search
    /// would find whichever came first. Here an answer record contains the
    /// option code in its data.
    #[test]
    fn the_walk_is_not_confused_by_the_code_appearing_in_a_record() {
        let mut buf = vec![0x12, 0x34, 0x81, 0x82];
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x01]); // answers: 1
        buf.extend_from_slice(&[0x00, 0x00]); // authority: 0
        buf.extend_from_slice(&[0x00, 0x01]); // additional: 1
        buf.extend_from_slice(b"\x07missing\x07example\x03com\x00");
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN

        // A TXT answer whose text happens to contain the option code, a
        // plausible length, and a value — exactly what a search would match.
        // TXT rdata is length-prefixed, so the string is six bytes inside seven.
        buf.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        buf.extend_from_slice(&[0x00, 0x07]); // rdlength
        buf.extend_from_slice(&[0x06, 0x00, 0x0F, 0x00, 0x02, 0x00, 0x63]); // decoy

        // The real OPT record, carrying extended error 18.
        let mut option = OPTION_EXTENDED_ERROR.to_be_bytes().to_vec();
        option.extend_from_slice(&[0x00, 0x02, 0x00, 18]);
        buf.push(0x00);
        buf.extend_from_slice(&TYPE_OPT.to_be_bytes());
        buf.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&(option.len() as u16).to_be_bytes());
        buf.extend_from_slice(&option);

        let summary = dissect_dns(None, None, 53, 1, &buf).summary;
        assert!(
            summary.contains("not allowed to query this resolver"),
            "{summary}"
        );
        // 0x63 is 99; a search would have found the decoy and reported that.
        assert!(!summary.contains("extended error 99"), "found the decoy");
    }

    /// A response with no extended error falls back to the response code.
    #[test]
    fn without_an_extended_error_the_response_code_is_still_reported() {
        let r = dissect_dns(None, None, 53, 1, &failed_response(3));
        assert!(r.summary.contains("NXDOMAIN"), "{}", r.summary);
        assert!(extended_error(&failed_response(3)).is_none());
    }

    /// An unknown extended error keeps its number.
    #[test]
    fn an_unknown_extended_error_keeps_its_number() {
        let p = response_with_extended_error(2, 250, "");
        assert!(dissect_dns(None, None, 53, 1, &p)
            .summary
            .contains("extended error 250"));
    }

    /// A truncated or malformed OPT record must fall back rather than panic.
    #[test]
    fn a_malformed_opt_record_does_not_panic() {
        let full = response_with_extended_error(2, 15, "text");
        for cut in 12..full.len() {
            let r = dissect_dns(None, None, 53, 1, &full[..cut]);
            assert!(r.summary.starts_with("DNS"), "{}", r.summary);
        }
    }

    /// A query is a question, not a result, and carries no failure to report.
    #[test]
    fn a_query_is_not_given_a_response_code() {
        let payload = build_dns_query("example.com", 0x1234);
        let r = dissect_dns(None, None, 54321, 53, &payload);
        assert!(!r.summary.contains("rcode"), "{}", r.summary);
    }
}
