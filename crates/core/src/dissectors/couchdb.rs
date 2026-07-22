// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect CouchDB HTTP REST API (TCP 5984).
pub fn dissect_couchdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") || payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ") {
        "CouchDB REST request".to_string()
    } else if payload.starts_with(b"HTTP/") {
        "CouchDB REST response".to_string()
    } else {
        format!("CouchDB HTTP API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CouchDb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn couchdb_rest() {
        let r = dissect_couchdb(None, None, 40000, 5984, b"GET /_all_dbs HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::CouchDb);
        assert!(r.summary.contains("REST request"));
    }
}
