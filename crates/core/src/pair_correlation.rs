// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Prompt/Response Pair Correlation — matches AI requests to their responses
//! using four layered strategies:
//!
//! 1. **TCP Connection Tracking** — 5-tuple key matches request/response on
//!    the same connection; HTTP/2 Stream IDs disambiguate multiplexed streams.
//! 2. **HTTP Header Correlation** — provider-specific headers
//!    (`x-request-id`, `request-id`, `apim-request-id`, `traceparent`, …).
//! 3. **SSE Stream ID Tracking** — OpenAI `stream_id`, Anthropic
//!    `message_id` → `content_block` sequence.
//! 4. **Timing Fallback** — sequential request–response pairs on the same TCP
//!    stream matched by timestamp proximity.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// 5-tuple connection identifier (TCP/UDP).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub protocol: u8,
}

/// Correlation key that adds an optional HTTP/2 stream ID to the 5-tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationKey {
    pub five_tuple: FiveTuple,
    pub http2_stream_id: Option<u32>,
}

impl From<FiveTuple> for CorrelationKey {
    fn from(ft: FiveTuple) -> Self {
        Self {
            five_tuple: ft,
            http2_stream_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Correlation header sources
// ---------------------------------------------------------------------------

/// Identifies which HTTP header supplied the correlation ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CorrelationHeaderSource {
    /// `x-request-id` — OpenAI, Fireworks
    XRequestId,
    /// `request-id` — Anthropic
    RequestId,
    /// `x-goog-request-params` (base64-decoded payload) — Google
    XGoogRequestParams,
    /// `apim-request-id` — Azure
    ApimRequestId,
    /// `traceparent` — W3C Trace Context
    Traceparent,
    /// `x-trace-id` — generic
    XTraceId,
}

impl std::fmt::Display for CorrelationHeaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XRequestId => write!(f, "x-request-id"),
            Self::RequestId => write!(f, "request-id"),
            Self::XGoogRequestParams => write!(f, "x-goog-request-params"),
            Self::ApimRequestId => write!(f, "apim-request-id"),
            Self::Traceparent => write!(f, "traceparent"),
            Self::XTraceId => write!(f, "x-trace-id"),
        }
    }
}

// ---------------------------------------------------------------------------
// Correlation method
// ---------------------------------------------------------------------------

/// Which strategy produced the correlation.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationMethod {
    /// 5-tuple / TCP connection tracking (Strategy 1)
    TcpConnection,
    /// HTTP header correlation (Strategy 2)
    HttpHeader(CorrelationHeaderSource),
    /// SSE stream ID tracking (Strategy 3)
    SseStreamId,
    /// Timing-based fallback (Strategy 4)
    TimingFallback,
}

impl std::fmt::Display for CorrelationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TcpConnection => write!(f, "tcp_connection"),
            Self::HttpHeader(src) => write!(f, "http_header({src})"),
            Self::SseStreamId => write!(f, "sse_stream_id"),
            Self::TimingFallback => write!(f, "timing_fallback"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// Correlation information attached to a request or response.
#[derive(Debug, Clone)]
pub struct CorrelationInfo {
    /// The unique correlation identifier (from header, stream ID, or computed).
    pub correlation_id: Option<String>,
    /// Which strategy produced this correlation.
    pub method: CorrelationMethod,
    /// Confidence level 0.0–1.0.
    pub confidence: f32,
    /// HTTP/2 stream ID (if multiplexed).
    pub http2_stream_id: Option<u32>,
    // HTTP request metadata
    pub request_method: Option<String>,
    pub request_path: Option<String>,
    // HTTP response metadata
    pub response_status: Option<u16>,
    // SSE tracking
    pub stream_session_id: Option<String>,
}

#[allow(dead_code)]
impl CorrelationInfo {
    fn with_correlation_id(mut self, id: String) -> Self {
        self.correlation_id = Some(id);
        self
    }

    fn with_confidence(mut self, c: f32) -> Self {
        self.confidence = c;
        self
    }
}

/// A completed correlated request–response pair.
#[derive(Debug, Clone)]
pub struct CorrelatedPair {
    pub correlation_id: Option<String>,
    pub method: CorrelationMethod,
    pub confidence: f32,

    pub request_timestamp: DateTime<Utc>,
    pub response_timestamp: Option<DateTime<Utc>>,

    pub request_method: Option<String>,
    pub request_path: Option<String>,
    pub response_status: Option<u16>,

    pub http2_stream_id: Option<u32>,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingRequest {
    key: CorrelationKey,
    timestamp: DateTime<Utc>,
    payload_hash: [u8; 32],
    correlation_id: Option<String>,
    request_method: Option<String>,
    request_path: Option<String>,
    http2_stream_id: Option<u32>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SseSession {
    stream_id: Option<String>,
    message_id: Option<String>,
    content_block_sequence: u32,
    start_time: DateTime<Utc>,
    correlation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP header extraction helpers
// ---------------------------------------------------------------------------

/// Extract the value of a named header from raw HTTP bytes.
/// Searches line-by-line after the request/status line, case-insensitively.
fn extract_header(payload: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.lines();
    // Skip the request/status line.
    lines.next()?;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            let v = value.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Detect all known correlation headers in an HTTP payload.
/// Returns `(header_source, header_value)` for the first match found, in
/// priority order.
fn detect_correlation_header(payload: &[u8]) -> Option<(CorrelationHeaderSource, String)> {
    for (name, source) in [
        ("x-request-id", CorrelationHeaderSource::XRequestId),
        ("apim-request-id", CorrelationHeaderSource::ApimRequestId),
        ("request-id", CorrelationHeaderSource::RequestId),
        ("x-trace-id", CorrelationHeaderSource::XTraceId),
        ("traceparent", CorrelationHeaderSource::Traceparent),
    ] {
        if let Some(val) = extract_header(payload, name) {
            return Some((source, val));
        }
    }
    // x-goog-request-params has a base64 value — just record the header presence.
    if let Some(val) = extract_header(payload, "x-goog-request-params") {
        return Some((
            CorrelationHeaderSource::XGoogRequestParams,
            val,
        ));
    }
    None
}

/// Try to extract a correlation ID from SSE event data (strategy 3).
fn detect_sse_correlation_id(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let body = text
        .strip_prefix("data: ")
        .or_else(|| text.strip_prefix("data:"))
        .unwrap_or(text)
        .trim();

    // OpenAI Response API: `stream_id` field in the event
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(sid) = val.get("stream_id").and_then(|v| v.as_str()) {
            return Some(format!("openai_stream:{}", sid));
        }
        // Anthropic: `message.id` in message_start event
        if val.get("type").and_then(|v| v.as_str()) == Some("message_start") {
            if let Some(mid) = val
                .get("message")
                .and_then(|m| m.get("id"))
                .and_then(|v| v.as_str())
            {
                return Some(format!("anthropic_msg:{}", mid));
            }
        }
    }
    None
}

/// Detect HTTP method + path from an HTTP request.
fn detect_http_request_info(payload: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(payload).ok()?;
    let first = text.lines().next()?;
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0];
    if ![
        "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE",
    ]
    .contains(&method)
    {
        return None;
    }
    Some((method.to_string(), parts[1].to_string()))
}

/// Detect HTTP response status code.
fn detect_http_response_status(payload: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(payload).ok()?;
    let first = text.lines().next()?;
    let parts: Vec<&str> = first.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    if !parts[0].starts_with("HTTP/") {
        return None;
    }
    parts[1].parse().ok()
}

/// Hash the payload for deduplication.
fn hash_payload(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

// ---------------------------------------------------------------------------
// PairCorrelationEngine
// ---------------------------------------------------------------------------

/// The main engine implementing all four pair-correlation strategies.
///
/// A request is observed first and held as pending; the response that follows
/// on the same flow is matched back to it. This pair carries no correlation
/// header, so it falls through to the timing strategy — the response still
/// reports which request it answered.
///
/// ```
/// use chrono::Utc;
/// use netscope_core::pair_correlation::{FiveTuple, PairCorrelationEngine};
///
/// let mut engine = PairCorrelationEngine::new();
/// let flow = FiveTuple {
///     src_ip: "10.0.0.1".parse().unwrap(),
///     src_port: 40000,
///     dst_ip: "10.0.0.2".parse().unwrap(),
///     dst_port: 80,
///     protocol: 6, // TCP
/// };
///
/// engine.observe_request(&flow, b"GET /v1/models HTTP/1.1\r\n\r\n", Utc::now(), None);
/// let info = engine
///     .observe_response(&flow, b"HTTP/1.1 200 OK\r\n\r\n", Utc::now(), None)
///     .expect("the response is matched back to the pending request");
///
/// assert_eq!(info.request_method.as_deref(), Some("GET"));
/// assert_eq!(info.request_path.as_deref(), Some("/v1/models"));
/// assert_eq!(info.response_status, Some(200));
/// ```
#[derive(Debug, Clone)]
pub struct PairCorrelationEngine {
    /// Pending requests awaiting responses (keyed by correlation key).
    pending: HashMap<CorrelationKey, Vec<PendingRequest>>,
    /// Active SSE streaming sessions (keyed by internal session token).
    sse_sessions: HashMap<String, SseSession>,
    /// Completed correlated pairs.
    completed: Vec<CorrelatedPair>,
    /// Last request timestamp per 5-tuple (for timing fallback).
    last_request_time: HashMap<FiveTuple, DateTime<Utc>>,
    /// Time window (ms) for timing fallback matching.
    timing_window_ms: u64,
}

impl Default for PairCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PairCorrelationEngine {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            sse_sessions: HashMap::new(),
            completed: Vec::new(),
            last_request_time: HashMap::new(),
            timing_window_ms: 5000,
        }
    }

    pub fn with_timing_window(mut self, ms: u64) -> Self {
        self.timing_window_ms = ms;
        self
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Observe a request packet. Returns correlation info if one is already
    /// derivable from headers alone (confidence may be low until the response
    /// arrives).
    pub fn observe_request(
        &mut self,
        five_tuple: &FiveTuple,
        payload: &[u8],
        timestamp: DateTime<Utc>,
        http2_stream_id: Option<u32>,
    ) -> CorrelationInfo {
        let key = CorrelationKey {
            five_tuple: five_tuple.clone(),
            http2_stream_id,
        };

        // Strategy 2: try header-based correlation ID.
        let header_correlation = detect_correlation_header(payload);

        let (correlation_id, correlation_method, confidence) = match &header_correlation {
            Some((src, id)) => (
                Some(id.clone()),
                CorrelationMethod::HttpHeader(src.clone()),
                0.9,
            ),
            None => {
                // Strategy 1: TCP connection tracking (5-tuple)
                (None, CorrelationMethod::TcpConnection, 0.7)
            }
        };

        // Extract HTTP request info for the record.
        let (req_method, req_path) = detect_http_request_info(payload).unzip();

        let payload_hash = hash_payload(payload);

        // Strategy 3: check if this is an SSE response carrying a stream ID.
        let sse_id = detect_sse_correlation_id(payload);
        if let Some(sid) = &sse_id {
            // Start tracking this SSE session.
            self.sse_sessions.insert(
                sid.clone(),
                SseSession {
                    stream_id: Some(sid.clone()),
                    message_id: None,
                    content_block_sequence: 0,
                    start_time: timestamp,
                    correlation_id: correlation_id.clone(),
                },
            );
        }

        // Store pending request for response matching.
        let pending = PendingRequest {
            key: key.clone(),
            timestamp,
            payload_hash,
            correlation_id: correlation_id.clone(),
            request_method: req_method.clone(),
            request_path: req_path.clone(),
            http2_stream_id,
        };
        self.pending.entry(key).or_default().push(pending);
        self.last_request_time
            .insert(five_tuple.clone(), timestamp);

        CorrelationInfo {
            correlation_id,
            method: correlation_method,
            confidence,
            http2_stream_id,
            request_method: req_method,
            request_path: req_path,
            response_status: None,
            stream_session_id: sse_id,
        }
    }

    /// Observe a response packet. Returns `Some(CorrelationInfo)` if a
    /// matching pending request was found, or if headers provide an ID.
    pub fn observe_response(
        &mut self,
        five_tuple: &FiveTuple,
        payload: &[u8],
        timestamp: DateTime<Utc>,
        http2_stream_id: Option<u32>,
    ) -> Option<CorrelationInfo> {
        let key = CorrelationKey {
            five_tuple: five_tuple.clone(),
            http2_stream_id,
        };

        // Strategy 2: try header-based correlation ID in response.
        let header_correlation = detect_correlation_header(payload);
        let response_status = detect_http_response_status(payload);

        // Try each strategy in order.
        let result = self
            .try_header_match(&key, &header_correlation, timestamp, response_status)
            .or_else(|| {
                self.try_sse_match(payload, timestamp, five_tuple, response_status)
            })
            .or_else(|| {
                self.try_timing_match(five_tuple, timestamp, http2_stream_id, response_status)
            })
            .or_else(|| {
                // No request matched — still report header info if available.
                header_correlation.as_ref().map(|(src, id)| {
                    self.completed.push(CorrelatedPair {
                        correlation_id: Some(id.clone()),
                        method: CorrelationMethod::HttpHeader(src.clone()),
                        confidence: 0.5,
                        request_timestamp: timestamp,
                        response_timestamp: Some(timestamp),
                        request_method: None,
                        request_path: None,
                        response_status,
                        http2_stream_id,
                    });
                    CorrelationInfo {
                        correlation_id: Some(id.clone()),
                        method: CorrelationMethod::HttpHeader(src.clone()),
                        confidence: 0.5,
                        http2_stream_id,
                        request_method: None,
                        request_path: None,
                        response_status,
                        stream_session_id: None,
                    }
                })
            });

        result
    }

    /// Return all completed correlated pairs.
    pub fn completed_pairs(&self) -> &[CorrelatedPair] {
        &self.completed
    }

    /// Drain completed pairs.
    pub fn drain_completed(&mut self) -> Vec<CorrelatedPair> {
        std::mem::take(&mut self.completed)
    }

    /// Number of pending (unmatched) requests.
    pub fn pending_count(&self) -> usize {
        self.pending.values().map(|v| v.len()).sum()
    }

    /// Number of active SSE sessions.
    pub fn active_sse_sessions(&self) -> usize {
        self.sse_sessions.len()
    }

    // -----------------------------------------------------------------------
    // Internal strategy implementations
    // -----------------------------------------------------------------------

    /// Strategy 2: match by correlation ID in HTTP headers.
    fn try_header_match(
        &mut self,
        key: &CorrelationKey,
        header_correlation: &Option<(CorrelationHeaderSource, String)>,
        timestamp: DateTime<Utc>,
        response_status: Option<u16>,
    ) -> Option<CorrelationInfo> {
        let (src, id) = header_correlation.as_ref()?;

        // Find a pending request with the same correlation ID.
        let pending_list = self.pending.get_mut(key)?;
        let pos = pending_list.iter().position(|p| {
            p.correlation_id.as_deref() == Some(id.as_str())
        })?;
        let pending = pending_list.remove(pos);
        if pending_list.is_empty() {
            self.pending.remove(key);
        }

        let req_method = pending.request_method.clone();
        let req_path = pending.request_path.clone();
        self.completed.push(CorrelatedPair {
            correlation_id: Some(id.clone()),
            method: CorrelationMethod::HttpHeader(src.clone()),
            confidence: 0.95,
            request_timestamp: pending.timestamp,
            response_timestamp: Some(timestamp),
            request_method: pending.request_method,
            request_path: pending.request_path,
            response_status,
            http2_stream_id: key.http2_stream_id,
        });

        Some(CorrelationInfo {
            correlation_id: Some(id.clone()),
            method: CorrelationMethod::HttpHeader(src.clone()),
            confidence: 0.95,
            http2_stream_id: key.http2_stream_id,
            request_method: req_method,
            request_path: req_path,
            response_status,
            stream_session_id: None,
        })
    }

    /// Strategy 3: match by SSE stream ID.
    fn try_sse_match(
        &mut self,
        payload: &[u8],
        timestamp: DateTime<Utc>,
        five_tuple: &FiveTuple,
        response_status: Option<u16>,
    ) -> Option<CorrelationInfo> {
        let sse_id = detect_sse_correlation_id(payload)?;

        // If this SSE event references an existing session, extend it.
        if let Some(session) = self.sse_sessions.get_mut(&sse_id) {
            session.content_block_sequence += 1;
            session.start_time = timestamp;
            // If the session already has a correlation_id from the request, use it.
            if let Some(cid) = &session.correlation_id {
                return Some(CorrelationInfo {
                    correlation_id: Some(cid.clone()),
                    method: CorrelationMethod::SseStreamId,
                    confidence: 0.85,
                    http2_stream_id: None,
                    request_method: None,
                    request_path: None,
                    response_status,
                    stream_session_id: Some(sse_id),
                });
            }
        }

        // Look for a pending request on this 5-tuple that has no header ID.
        let key = CorrelationKey {
            five_tuple: five_tuple.clone(),
            http2_stream_id: None,
        };
        let pending_list = self.pending.get_mut(&key)?;
        if pending_list.is_empty() {
            return None;
        }

        // Match the oldest pending request on this connection.
        let pending = pending_list.remove(0);
        if pending_list.is_empty() {
            self.pending.remove(&key);
        }

        // Register the SSE session.
        self.sse_sessions.insert(
            sse_id.clone(),
            SseSession {
                stream_id: Some(sse_id.clone()),
                message_id: None,
                content_block_sequence: 1,
                start_time: pending.timestamp,
                correlation_id: pending.correlation_id.clone(),
            },
        );

        let cid = pending.correlation_id.clone().unwrap_or_else(|| sse_id.clone());
        let req_method = pending.request_method.clone();
        let req_path = pending.request_path.clone();
        self.completed.push(CorrelatedPair {
            correlation_id: Some(cid.clone()),
            method: CorrelationMethod::SseStreamId,
            confidence: 0.8,
            request_timestamp: pending.timestamp,
            response_timestamp: Some(timestamp),
            request_method: pending.request_method,
            request_path: pending.request_path,
            response_status,
            http2_stream_id: None,
        });

        Some(CorrelationInfo {
            correlation_id: Some(cid),
            method: CorrelationMethod::SseStreamId,
            confidence: 0.8,
            http2_stream_id: None,
            request_method: req_method,
            request_path: req_path,
            response_status,
            stream_session_id: Some(sse_id),
        })
    }

    /// Strategy 4: timing-based fallback — match the most recent pending
    /// request on the same 5-tuple within the timing window.
    fn try_timing_match(
        &mut self,
        five_tuple: &FiveTuple,
        timestamp: DateTime<Utc>,
        http2_stream_id: Option<u32>,
        response_status: Option<u16>,
    ) -> Option<CorrelationInfo> {
        let key = CorrelationKey {
            five_tuple: five_tuple.clone(),
            http2_stream_id,
        };
        let pending_list = self.pending.get_mut(&key)?;

        // Get the most recent request on this 5-tuple.
        let last_req_time = self.last_request_time.get(five_tuple)?;
        let elapsed_ms = (timestamp - *last_req_time)
            .to_std()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);

        if elapsed_ms > self.timing_window_ms {
            return None;
        }

        // Match the most recent pending request.
        let pending = pending_list.pop()?;
        if pending_list.is_empty() {
            self.pending.remove(&key);
        }

        let cid = pending.correlation_id.clone().unwrap_or_else(|| {
            format!("timing:{}-{}-{}-{}", five_tuple.src_ip, five_tuple.src_port, five_tuple.dst_ip, five_tuple.dst_port)
        });
        let req_method = pending.request_method.clone();
        let req_path = pending.request_path.clone();
        let h2_stream = pending.http2_stream_id;
        self.completed.push(CorrelatedPair {
            correlation_id: Some(cid.clone()),
            method: CorrelationMethod::TimingFallback,
            confidence: 0.6,
            request_timestamp: pending.timestamp,
            response_timestamp: Some(timestamp),
            request_method: pending.request_method,
            request_path: pending.request_path,
            response_status,
            http2_stream_id: h2_stream,
        });

        Some(CorrelationInfo {
            correlation_id: Some(cid),
            method: CorrelationMethod::TimingFallback,
            confidence: 0.6,
            http2_stream_id,
            request_method: req_method,
            request_path: req_path,
            response_status,
            stream_session_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn tcp_tuple(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> FiveTuple {
        FiveTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: 6,
        }
    }

    // ---- Strategy 1: TCP Connection Tracking ----

    #[test]
    fn test_tcp_connection_request_response() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        // Request
        let req_info = engine.observe_request(&ft, b"POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\n\r\n", t0, None);
        assert_eq!(req_info.method, CorrelationMethod::TcpConnection);
        assert!((req_info.confidence - 0.7).abs() < 0.01);
        assert_eq!(req_info.request_method.as_deref(), Some("POST"));
        assert_eq!(req_info.request_path.as_deref(), Some("/v1/chat"));
        assert_eq!(engine.pending_count(), 1);

        // Response on same 5-tuple (timing match)
        let resp_info = engine.observe_response(
            &ft,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
            t0 + chrono::Duration::milliseconds(100),
            None,
        );
        assert!(resp_info.is_some());
        let info = resp_info.unwrap();
        assert_eq!(info.method, CorrelationMethod::TimingFallback);
        assert_eq!(info.response_status, Some(200));
        assert_eq!(engine.pending_count(), 0);
        assert_eq!(engine.completed_pairs().len(), 1);
    }

    // ---- Strategy 2: HTTP Header Correlation ----

    #[test]
    fn test_x_request_id_correlation() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        // Request with x-request-id
        let req_payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nx-request-id: req_abc123\r\n\r\n{\"model\":\"gpt-4\"}";
        let req_info = engine.observe_request(&ft, req_payload, t0, None);
        assert_eq!(req_info.correlation_id.as_deref(), Some("req_abc123"));
        assert_eq!(
            req_info.method,
            CorrelationMethod::HttpHeader(CorrelationHeaderSource::XRequestId)
        );

        // Response with matching x-request-id
        let resp_payload = b"HTTP/1.1 200 OK\r\nx-request-id: req_abc123\r\nContent-Type: application/json\r\n\r\n{\"choices\":[]}";
        let resp_info = engine.observe_response(
            &ft,
            resp_payload,
            t0 + chrono::Duration::milliseconds(200),
            None,
        );
        assert!(resp_info.is_some());
        let info = resp_info.unwrap();
        assert_eq!(info.correlation_id.as_deref(), Some("req_abc123"));
        assert_eq!(info.confidence, 0.95);
        assert_eq!(info.response_status, Some(200));
    }

    #[test]
    fn test_apim_request_id_correlation() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        let req_payload = b"POST /openai/deployments/gpt-4/chat HTTP/1.1\r\nHost: my-resource.openai.azure.com\r\napim-request-id: azure_id_001\r\n\r\n{}";
        engine.observe_request(&ft, req_payload, t0, None);

        let resp_payload = b"HTTP/1.1 200 OK\r\napim-request-id: azure_id_001\r\n\r\n{}";
        let info = engine.observe_response(&ft, resp_payload, t0 + chrono::Duration::milliseconds(150), None);
        assert!(info.is_some());
        assert_eq!(
            info.unwrap().correlation_id.as_deref(),
            Some("azure_id_001")
        );
    }

    #[test]
    fn test_anthropic_request_id_correlation() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        let req_payload = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nrequest-id: ant_req_456\r\n\r\n{}";
        engine.observe_request(&ft, req_payload, t0, None);

        let resp_payload = b"HTTP/1.1 200 OK\r\nrequest-id: ant_req_456\r\n\r\n{}";
        let info = engine.observe_response(&ft, resp_payload, t0 + chrono::Duration::milliseconds(100), None);
        assert!(info.is_some());
        assert_eq!(info.unwrap().correlation_id.as_deref(), Some("ant_req_456"));
    }

    #[test]
    fn test_http_header_mismatch_not_matched() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        let req_payload = b"POST /v1/chat HTTP/1.1\r\nx-request-id: req_001\r\n\r\n";
        engine.observe_request(&ft, req_payload, t0, None);

        // Response with different x-request-id — should not match via header,
        // fall back to timing.
        let resp_payload = b"HTTP/1.1 200 OK\r\nx-request-id: req_002\r\n\r\n";
        let info = engine.observe_response(&ft, resp_payload, t0 + chrono::Duration::milliseconds(50), None);
        assert!(info.is_some());
        // The header ID is different, so header match fails; should fall to timing.
        assert_eq!(info.unwrap().method, CorrelationMethod::TimingFallback);
    }

    // ---- Strategy 3: SSE Stream ID ----

    #[test]
    fn test_openai_sse_stream_id() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        // Request
        engine.observe_request(
            &ft,
            b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{}",
            t0,
            None,
        );

        // SSE response with stream_id
        let sse_payload = b"data: {\"type\":\"response.created\",\"stream_id\":\"str_789\"}\n\n";
        let info = engine.observe_response(&ft, sse_payload, t0 + chrono::Duration::milliseconds(100), None);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.stream_session_id.as_deref(), Some("openai_stream:str_789"));
        assert_eq!(info.method, CorrelationMethod::SseStreamId);
        assert_eq!(engine.active_sse_sessions(), 1);
    }

    #[test]
    fn test_anthropic_sse_message_id() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(
            &ft,
            b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n{}",
            t0,
            None,
        );

        // Anthropic message_start event
        let sse_payload = b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_0123\",\"content\":[]}}\n\n";
        let info = engine.observe_response(&ft, sse_payload, t0 + chrono::Duration::milliseconds(50), None);
        assert!(info.is_some());
        assert_eq!(
            info.unwrap().stream_session_id.as_deref(),
            Some("anthropic_msg:msg_0123")
        );
    }

    // ---- Strategy 4: Timing Fallback ----

    #[test]
    fn test_timing_fallback_within_window() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(
            &ft,
            b"POST /v1/chat HTTP/1.1\r\n\r\n",
            t0,
            None,
        );

        let info = engine.observe_response(
            &ft,
            b"HTTP/1.1 200 OK\r\n\r\n",
            t0 + chrono::Duration::milliseconds(200),
            None,
        );
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.method, CorrelationMethod::TimingFallback);
        assert_eq!(info.confidence, 0.6);
    }

    #[test]
    fn test_timing_fallback_outside_window() {
        let mut engine = PairCorrelationEngine::new().with_timing_window(100);
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(
            &ft,
            b"POST /v1/chat HTTP/1.1\r\n\r\n",
            t0,
            None,
        );

        // Response arrives after timing window — no match.
        let info = engine.observe_response(
            &ft,
            b"HTTP/1.1 200 OK\r\n\r\n",
            t0 + chrono::Duration::milliseconds(200),
            None,
        );
        assert!(info.is_none());
    }

    // ---- HTTP/2 Stream ID ----

    #[test]
    fn test_http2_stream_id_multiplexing() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        // Two requests on different HTTP/2 streams
        engine.observe_request(&ft, b"stream 1 request", t0, Some(1));
        engine.observe_request(&ft, b"stream 2 request", t0 + chrono::Duration::milliseconds(10), Some(3));

        // Responses on correct streams
        let r1 = engine.observe_response(&ft, b"stream 1 response", t0 + chrono::Duration::milliseconds(50), Some(1));
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().http2_stream_id, Some(1));

        let r2 = engine.observe_response(&ft, b"stream 2 response", t0 + chrono::Duration::milliseconds(60), Some(3));
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().http2_stream_id, Some(3));

        assert_eq!(engine.completed_pairs().len(), 2);
    }

    // ---- Helper functions ----

    #[test]
    fn test_extract_header() {
        let payload = b"POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nx-request-id: abc123\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(
            extract_header(payload, "x-request-id"),
            Some("abc123".into())
        );
        assert_eq!(
            extract_header(payload, "content-type"),
            Some("application/json".into())
        );
        assert_eq!(extract_header(payload, "nonexistent"), None);
    }

    #[test]
    fn test_detect_correlation_header_priority() {
        // x-request-id has highest priority
        let payload = b"HTTP/1.1 200 OK\r\nx-request-id: first\r\ntraceparent: second\r\n\r\n";
        let result = detect_correlation_header(payload);
        assert!(result.is_some());
        let (src, val) = result.unwrap();
        assert_eq!(src, CorrelationHeaderSource::XRequestId);
        assert_eq!(val, "first");
    }

    #[test]
    fn test_detect_http_request_info() {
        let payload = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let (method, path) = detect_http_request_info(payload).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn test_detect_http_response_status() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        assert_eq!(detect_http_response_status(payload), Some(200));

        let payload2 = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(detect_http_response_status(payload2), Some(404));

        let payload3 = b"not http";
        assert_eq!(detect_http_response_status(payload3), None);
    }

    #[test]
    fn test_detect_sse_correlation_id_openai() {
        let payload = b"data: {\"type\":\"response.created\",\"stream_id\":\"str_001\"}\n\n";
        let id = detect_sse_correlation_id(payload);
        assert_eq!(id, Some("openai_stream:str_001".into()));
    }

    #[test]
    fn test_detect_sse_correlation_id_anthropic() {
        let payload = b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_987\"}}\n\n";
        let id = detect_sse_correlation_id(payload);
        assert_eq!(id, Some("anthropic_msg:msg_987".into()));
    }

    #[test]
    fn test_detect_sse_correlation_id_non_sse() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(detect_sse_correlation_id(payload), None);
    }

    // ---- Engine lifecycle ----

    #[test]
    fn test_drain_completed() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(&ft, b"GET / HTTP/1.1\r\n\r\n", t0, None);
        engine.observe_response(&ft, b"HTTP/1.1 200 OK\r\n\r\n", t0 + chrono::Duration::milliseconds(50), None);

        assert_eq!(engine.drain_completed().len(), 1);
        assert_eq!(engine.completed_pairs().len(), 0);
    }

    #[test]
    fn test_pending_count() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );

        engine.observe_request(&ft, b"GET /1 HTTP/1.1\r\n\r\n", Utc::now(), None);
        engine.observe_request(&ft, b"GET /2 HTTP/1.1\r\n\r\n", Utc::now(), None);
        assert_eq!(engine.pending_count(), 2);
    }

    #[test]
    fn test_with_timing_window() {
        let engine = PairCorrelationEngine::new().with_timing_window(1000);
        assert_eq!(engine.timing_window_ms, 1000);
    }

    #[test]
    fn test_five_tuple_hash_and_eq() {
        let ft1 = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let ft2 = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let ft3 = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        assert_eq!(ft1, ft2);
        assert_ne!(ft1, ft3);
    }

    #[test]
    fn test_correlation_key_from_five_tuple() {
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let ck: CorrelationKey = ft.clone().into();
        assert_eq!(ck.five_tuple, ft);
        assert_eq!(ck.http2_stream_id, None);
    }

    #[test]
    fn test_ipv6_support() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V6(Ipv6Addr::new(0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0x1)),
            50000,
            IpAddr::V6(Ipv6Addr::new(0x26, 0x00, 0x19, 0x01, 0, 0, 0, 0x2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(&ft, b"GET / HTTP/1.1\r\nx-request-id: ipv6_test\r\n\r\n", t0, None);
        let info = engine.observe_response(
            &ft,
            b"HTTP/1.1 200 OK\r\nx-request-id: ipv6_test\r\n\r\n",
            t0 + chrono::Duration::milliseconds(50),
            None,
        );
        assert!(info.is_some());
        assert_eq!(info.unwrap().correlation_id.as_deref(), Some("ipv6_test"));
    }

    #[test]
    fn test_no_response_no_match() {
        let mut engine = PairCorrelationEngine::new();
        let ft = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );

        engine.observe_request(&ft, b"GET / HTTP/1.1\r\n\r\n", Utc::now(), None);
        // No response — pending stays.
        assert_eq!(engine.pending_count(), 1);
        assert_eq!(engine.completed_pairs().len(), 0);
    }

    #[test]
    fn test_multiple_connections_independent() {
        let mut engine = PairCorrelationEngine::new();
        let ft1 = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let ft2 = tcp_tuple(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50002,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let t0 = Utc::now();

        engine.observe_request(&ft1, b"GET /1 HTTP/1.1\r\nx-request-id: a\r\n\r\n", t0, None);
        engine.observe_request(&ft2, b"GET /2 HTTP/1.1\r\nx-request-id: b\r\n\r\n", t0, None);

        let r2 = engine.observe_response(&ft2, b"HTTP/1.1 200 OK\r\nx-request-id: b\r\n\r\n", t0 + chrono::Duration::milliseconds(10), None);
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().correlation_id.as_deref(), Some("b"));

        let r1 = engine.observe_response(&ft1, b"HTTP/1.1 200 OK\r\nx-request-id: a\r\n\r\n", t0 + chrono::Duration::milliseconds(20), None);
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().correlation_id.as_deref(), Some("a"));

        assert_eq!(engine.completed_pairs().len(), 2);
    }

    #[test]
    fn test_goog_request_params_detected() {
        let payload = b"POST /v1/models/gemini-pro:generateContent HTTP/1.1\r\nx-goog-request-params: project=test\r\n\r\n";
        let (src, val) = detect_correlation_header(payload).unwrap();
        assert_eq!(src, CorrelationHeaderSource::XGoogRequestParams);
        assert_eq!(val, "project=test");
    }

    #[test]
    fn test_traceparent_detected() {
        let payload = b"GET / HTTP/1.1\r\ntraceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n\r\n";
        let (src, val) = detect_correlation_header(payload).unwrap();
        assert_eq!(src, CorrelationHeaderSource::Traceparent);
        assert!(val.contains("0af7651916cd43dd8448eb211c80319c"));
    }

    #[test]
    fn test_correlation_method_display() {
        assert_eq!(CorrelationMethod::TcpConnection.to_string(), "tcp_connection");
        assert_eq!(
            CorrelationMethod::HttpHeader(CorrelationHeaderSource::XRequestId).to_string(),
            "http_header(x-request-id)"
        );
        assert_eq!(CorrelationMethod::SseStreamId.to_string(), "sse_stream_id");
        assert_eq!(CorrelationMethod::TimingFallback.to_string(), "timing_fallback");
    }
}
