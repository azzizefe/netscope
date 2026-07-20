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
            } else if let Some(reason) = failure_reason(&pkt) {
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

    /// A query is a question, not a result, and carries no failure to report.
    #[test]
    fn a_query_is_not_given_a_response_code() {
        let payload = build_dns_query("example.com", 0x1234);
        let r = dissect_dns(None, None, 54321, 53, &payload);
        assert!(!r.summary.contains("rcode"), "{}", r.summary);
    }
}
