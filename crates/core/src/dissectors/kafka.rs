// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Kafka's wire protocol.
//!
//! Every request names an API key, and that key is the whole story: a Produce
//! is a message being written, a Fetch is one being read, and a JoinGroup or
//! Heartbeat is a consumer negotiating its share of the work. Reporting it as a
//! bare number leaves the reader to look it up, when the difference between
//! "traffic is flowing" and "consumers keep rebalancing" is exactly what a
//! capture is being read to find out.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// A length, then the API key, version, correlation id and client id.
const HEADER: usize = 12;

/// API keys (Kafka protocol guide). The list covers what appears in ordinary
/// operation; an unrecognised key still reports its number, since new ones are
/// added with every release.
fn api_name(key: u16) -> Option<&'static str> {
    Some(match key {
        0 => "Produce (write)",
        1 => "Fetch (read)",
        2 => "ListOffsets",
        3 => "Metadata",
        8 => "OffsetCommit",
        9 => "OffsetFetch",
        10 => "FindCoordinator",
        11 => "JoinGroup",
        12 => "Heartbeat",
        13 => "LeaveGroup",
        14 => "SyncGroup",
        15 => "DescribeGroups",
        16 => "ListGroups",
        17 => "SaslHandshake",
        18 => "ApiVersions",
        19 => "CreateTopics",
        20 => "DeleteTopics",
        21 => "DeleteRecords",
        22 => "InitProducerId",
        24 => "AddPartitionsToTxn",
        25 => "AddOffsetsToTxn",
        26 => "EndTxn",
        28 => "TxnOffsetCommit",
        32 => "DescribeConfigs",
        33 => "AlterConfigs",
        36 => "SaslAuthenticate",
        37 => "CreatePartitions",
        42 => "DeleteGroups",
        43 => "ElectLeaders",
        44 => "IncrementalAlterConfigs",
        47 => "OffsetDelete",
        50 => "DescribeUserScramCredentials",
        60 => "DescribeCluster",
        _ => return None,
    })
}

/// Read the client id, which every request carries after the correlation id.
///
/// Clients set it to something meaningful — usually an application name — so it
/// says *which* service is talking rather than only that something is.
fn client_id(payload: &[u8]) -> Option<String> {
    let len = i16::from_be_bytes([*payload.get(HEADER)?, *payload.get(HEADER + 1)?]);
    // A negative length means the field is null, which is legal.
    if len <= 0 {
        return None;
    }
    let text = payload.get(HEADER + 2..HEADER + 2 + len as usize)?;
    let text = std::str::from_utf8(text).ok()?;
    // A client id is an identifier; anything else means the offsets are wrong
    // and the field would render as noise.
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    Some(text.to_string())
}

/// Dissect a Kafka segment (TCP 9092).
pub fn dissect_kafka(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER {
        format!("Kafka ({})", super::bytes(payload.len() as u64))
    } else {
        let api_key = u16::from_be_bytes([payload[4], payload[5]]);
        let api_version = u16::from_be_bytes([payload[6], payload[7]]);
        let name = match api_name(api_key) {
            Some(n) => n.to_string(),
            None => format!("API key {api_key}"),
        };
        match client_id(payload) {
            Some(client) => format!(
                "Kafka {name} v{api_version} — from {}",
                super::truncate(&client, 32)
            ),
            None => format!("Kafka {name} v{api_version}"),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Kafka,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Kafka request header, optionally naming a client.
    fn request(api_key: u16, api_version: u16, client: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes()); // correlation id
        match client {
            Some(c) => {
                body.extend_from_slice(&(c.len() as i16).to_be_bytes());
                body.extend_from_slice(c.as_bytes());
            }
            None => body.extend_from_slice(&(-1i16).to_be_bytes()),
        }
        let mut p = (body.len() as u32).to_be_bytes().to_vec();
        p.extend_from_slice(&body);
        p
    }

    /// The distinction the whole protocol turns on: is a message being written
    /// or read?
    #[test]
    fn produce_and_fetch_are_named() {
        let r = dissect_kafka(None, None, 40000, 9092, &request(0, 9, None));
        assert_eq!(r.protocol, Protocol::Kafka);
        assert_eq!(r.summary, "Kafka Produce (write) v9");
        assert_eq!(
            dissect_kafka(None, None, 1, 9092, &request(1, 13, None)).summary,
            "Kafka Fetch (read) v13"
        );
    }

    /// A run of these means consumers are rebalancing rather than working,
    /// which looks like a stall from the application's side and is otherwise
    /// hard to tell apart from ordinary traffic.
    #[test]
    fn consumer_group_traffic_is_named() {
        assert_eq!(
            dissect_kafka(None, None, 1, 9092, &request(11, 7, None)).summary,
            "Kafka JoinGroup v7"
        );
        assert_eq!(
            dissect_kafka(None, None, 1, 9092, &request(12, 4, None)).summary,
            "Kafka Heartbeat v4"
        );
    }

    /// The client id is set by the application, so it names which service is
    /// talking.
    #[test]
    fn the_client_id_names_the_application() {
        let r = dissect_kafka(None, None, 1, 9092, &request(0, 9, Some("orders-service")));
        assert_eq!(r.summary, "Kafka Produce (write) v9 — from orders-service");
    }

    /// A null client id is legal and must not read as a parse failure.
    #[test]
    fn a_null_client_id_is_handled() {
        let r = dissect_kafka(None, None, 1, 9092, &request(3, 12, None));
        assert_eq!(r.summary, "Kafka Metadata v12");
    }

    /// The version matters operationally: a client stuck on an old one cannot
    /// use newer broker features, and that is visible here.
    #[test]
    fn the_api_version_is_reported() {
        assert!(dissect_kafka(None, None, 1, 9092, &request(1, 4, None))
            .summary
            .ends_with("v4"));
        assert!(dissect_kafka(None, None, 1, 9092, &request(1, 15, None))
            .summary
            .ends_with("v15"));
    }

    /// New API keys arrive with every Kafka release, so an unknown one reports
    /// its number rather than being dropped.
    #[test]
    fn an_unknown_api_key_reports_its_number() {
        let r = dissect_kafka(None, None, 1, 9092, &request(200, 0, None));
        assert_eq!(r.summary, "Kafka API key 200 v0");
    }

    /// Binary where the client id should be means the offsets are wrong, so
    /// the field is dropped rather than rendered as noise.
    #[test]
    fn a_nonsense_client_id_is_not_shown() {
        let mut p = request(0, 9, None);
        p.truncate(HEADER);
        p.extend_from_slice(&4i16.to_be_bytes());
        p.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        let r = dissect_kafka(None, None, 1, 9092, &p);
        assert_eq!(r.summary, "Kafka Produce (write) v9");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_kafka(None, None, 1, 9092, &[0x00, 0x00, 0x00, 0x10]);
        assert_eq!(r.summary, "Kafka (4 bytes)");
    }
}
