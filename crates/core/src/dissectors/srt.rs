// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub dns_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

pub struct SrtState {
    pub dns_queries: HashMap<DnsKey, Instant>,
    pub http_requests: HashMap<HttpKey, Vec<Instant>>, // list of request times in order
}

fn get_srt_state() -> &'static Mutex<SrtState> {
    static STATE: OnceLock<Mutex<SrtState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(SrtState {
            dns_queries: HashMap::new(),
            http_requests: HashMap::new(),
        })
    })
}

/// Record a DNS packet and return the response time if it is a response matching a previous query.
pub fn record_dns(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Duration> {
    let src = src_ip?;
    let dst = dst_ip?;
    if payload.len() < 4 {
        return None;
    }

    let dns_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;

    let mut guard = get_srt_state().lock().unwrap();
    if !is_response {
        // Query: record client request time
        let key = DnsKey {
            client_ip: src,
            client_port: src_port,
            server_ip: dst,
            dns_id,
        };
        guard.dns_queries.insert(key, Instant::now());
        None
    } else {
        // Response: lookup query from the client (swapped src/dst)
        let key = DnsKey {
            client_ip: dst,
            client_port: dst_port,
            server_ip: src,
            dns_id,
        };
        if let Some(req_time) = guard.dns_queries.remove(&key) {
            Some(req_time.elapsed())
        } else {
            None
        }
    }
}

/// Record an HTTP packet (via summary check or method/status extraction) and return response time.
pub fn record_http(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    summary: &str,
) -> Option<Duration> {
    let src = src_ip?;
    let dst = dst_ip?;

    let is_request = summary.contains("HTTP GET")
        || summary.contains("HTTP POST")
        || summary.contains("HTTP PUT")
        || summary.contains("HTTP DELETE");
    let is_response = summary.contains("HTTP/1.0") || summary.contains("HTTP/1.1");

    let mut guard = get_srt_state().lock().unwrap();
    if is_request {
        let key = HttpKey {
            client_ip: src,
            client_port: src_port,
            server_ip: dst,
            server_port: dst_port,
        };
        guard
            .http_requests
            .entry(key)
            .or_default()
            .push(Instant::now());
        None
    } else if is_response {
        // Response from server to client: key belongs to the client (swapped)
        let key = HttpKey {
            client_ip: dst,
            client_port: dst_port,
            server_ip: src,
            server_port: src_port,
        };
        if let Some(queue) = guard.http_requests.get_mut(&key) {
            if !queue.is_empty() {
                let req_time = queue.remove(0);
                if queue.is_empty() {
                    guard.http_requests.remove(&key);
                }
                return Some(req_time.elapsed());
            }
        }
        None
    } else {
        None
    }
}
