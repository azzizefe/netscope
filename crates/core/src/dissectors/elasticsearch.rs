// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Elasticsearch's internal transport protocol (TCP 9300).
//!
//! This is how nodes talk to each other, distinct from the HTTP API on 9200.
//! The status byte carries the two facts worth reading: whether a message is a
//! request or a response, and whether that response is an error. A cluster
//! whose internal traffic is mostly errors is failing in a way the HTTP API
//! will not show, because the client sees a slow query rather than a broken
//! node.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The marker bytes every transport message opens with.
const MARKER: &[u8] = b"ES";
/// Marker, message length, request id, then the status byte.
const OFFSET_STATUS: usize = 2 + 4 + 8;
/// Status, then the version.
const OFFSET_VERSION: usize = OFFSET_STATUS + 1;

/// Status bits (`TransportStatus`).
const STATUS_RESPONSE: u8 = 1 << 0;
const STATUS_ERROR: u8 = 1 << 1;
const STATUS_COMPRESS: u8 = 1 << 2;
const STATUS_HANDSHAKE: u8 = 1 << 3;

/// Dissect an Elasticsearch transport message.
pub fn dissect_elasticsearch(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = describe(payload).unwrap_or_else(|| {
        format!(
            "Elasticsearch transport ({})",
            super::bytes(payload.len() as u64)
        )
    });
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Elasticsearch,
        summary,
    }
}

fn describe(payload: &[u8]) -> Option<String> {
    if !payload.starts_with(MARKER) {
        return None;
    }
    let Some(&status) = payload.get(OFFSET_STATUS) else {
        return Some("Elasticsearch transport message".to_string());
    };
    let request_id = u64::from_be_bytes([
        *payload.get(6)?,
        *payload.get(7)?,
        *payload.get(8)?,
        *payload.get(9)?,
        *payload.get(10)?,
        *payload.get(11)?,
        *payload.get(12)?,
        *payload.get(13)?,
    ]);

    // A handshake is how a node checks it can speak to another at all, and it
    // carries the version that decides whether they can.
    if status & STATUS_HANDSHAKE != 0 {
        return Some(match version(payload) {
            Some(v) => format!("Elasticsearch handshake — version {v}"),
            None => "Elasticsearch handshake".to_string(),
        });
    }

    // An error response is the one worth spotting: the cluster is failing
    // internally while the HTTP API only shows a slow query.
    let kind = match (status & STATUS_RESPONSE != 0, status & STATUS_ERROR != 0) {
        (true, true) => "error response",
        (true, false) => "response",
        (false, _) => "request",
    };
    let compressed = if status & STATUS_COMPRESS != 0 {
        ", compressed"
    } else {
        ""
    };
    Some(format!(
        "Elasticsearch {kind} (id {request_id}{compressed})"
    ))
}

/// The wire version, which nodes use to decide whether they are compatible.
fn version(payload: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes([
        *payload.get(OFFSET_VERSION)?,
        *payload.get(OFFSET_VERSION + 1)?,
        *payload.get(OFFSET_VERSION + 2)?,
        *payload.get(OFFSET_VERSION + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a transport message with the given status and request id.
    fn message(status: u8, request_id: u64) -> Vec<u8> {
        let mut p = MARKER.to_vec();
        p.extend_from_slice(&64u32.to_be_bytes()); // message length
        p.extend_from_slice(&request_id.to_be_bytes());
        p.push(status);
        p.extend_from_slice(&8_00_00_99u32.to_be_bytes()); // version
        p
    }

    /// The direction is the first thing to establish, and neither was visible
    /// before: every message read as "transport message".
    #[test]
    fn requests_and_responses_are_distinguished() {
        let r = dissect_elasticsearch(None, None, 40000, 9300, &message(0, 42));
        assert_eq!(r.protocol, Protocol::Elasticsearch);
        assert_eq!(r.summary, "Elasticsearch request (id 42)");
        assert_eq!(
            dissect_elasticsearch(None, None, 9300, 1, &message(STATUS_RESPONSE, 42)).summary,
            "Elasticsearch response (id 42)"
        );
    }

    /// An error here means the cluster is failing internally, while the HTTP
    /// API on the other port shows only a slow query.
    #[test]
    fn an_error_response_is_called_out() {
        let r = dissect_elasticsearch(
            None,
            None,
            9300,
            1,
            &message(STATUS_RESPONSE | STATUS_ERROR, 7),
        );
        assert_eq!(r.summary, "Elasticsearch error response (id 7)");
    }

    /// The request id pairs a response with what asked for it, which is how a
    /// slow node is identified in an interleaved capture.
    #[test]
    fn the_request_id_pairs_the_two_halves() {
        let request = dissect_elasticsearch(None, None, 1, 9300, &message(0, 12345));
        let response = dissect_elasticsearch(None, None, 9300, 1, &message(STATUS_RESPONSE, 12345));
        assert!(request.summary.contains("id 12345"));
        assert!(response.summary.contains("id 12345"));
    }

    /// A handshake decides whether two nodes can talk at all, so its version
    /// is the useful field rather than a request id.
    #[test]
    fn a_handshake_reports_its_version() {
        let r = dissect_elasticsearch(None, None, 1, 9300, &message(STATUS_HANDSHAKE, 1));
        assert_eq!(r.summary, "Elasticsearch handshake — version 8000099");
    }

    /// Compression is worth noting because it explains why a message is far
    /// smaller than the data it carries.
    #[test]
    fn compression_is_noted() {
        let r = dissect_elasticsearch(
            None,
            None,
            1,
            9300,
            &message(STATUS_RESPONSE | STATUS_COMPRESS, 3),
        );
        assert_eq!(r.summary, "Elasticsearch response (id 3, compressed)");
    }

    /// Traffic without the marker is not this protocol.
    #[test]
    fn a_foreign_payload_is_not_claimed() {
        assert!(describe(b"GET / HTTP/1.1").is_none());
        assert!(describe(&[]).is_none());
        let r = dissect_elasticsearch(None, None, 1, 9300, b"GET /");
        assert_eq!(r.summary, "Elasticsearch transport (5 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_elasticsearch(None, None, 1, 9300, b"ES\x00\x00\x00\x10");
        assert_eq!(r.summary, "Elasticsearch transport message");
    }
}
