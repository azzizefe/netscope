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
}
