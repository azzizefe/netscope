use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::llm_analytics::LlmMetadata;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub type SessionId = u64;

fn next_session_id() -> SessionId {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

/// Supported AI provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AiProvider {
    Openai,
    Anthropic,
    Google,
    Azure,
    Cohere,
    Mistral,
    Groq,
    Together,
    Fireworks,
    Deepseek,
    Xai,
    Aws,
    Perplexity,
    Openrouter,
    Cloudflare,
    Kong,
    Vllm,
    Huggingface,
    Nvidia,
    Sglang,
    Litellm,
    Portkey,
    Helicone,
    Langfuse,
    Mlflow,
    Arize,
    Other(String),
}

impl fmt::Display for AiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiProvider::Openai => write!(f, "openai"),
            AiProvider::Anthropic => write!(f, "anthropic"),
            AiProvider::Google => write!(f, "google"),
            AiProvider::Azure => write!(f, "azure"),
            AiProvider::Cohere => write!(f, "cohere"),
            AiProvider::Mistral => write!(f, "mistral"),
            AiProvider::Groq => write!(f, "groq"),
            AiProvider::Together => write!(f, "together"),
            AiProvider::Fireworks => write!(f, "fireworks"),
            AiProvider::Deepseek => write!(f, "deepseek"),
            AiProvider::Xai => write!(f, "xai"),
            AiProvider::Aws => write!(f, "aws"),
            AiProvider::Perplexity => write!(f, "perplexity"),
            AiProvider::Openrouter => write!(f, "openrouter"),
            AiProvider::Cloudflare => write!(f, "cloudflare"),
            AiProvider::Kong => write!(f, "kong"),
            AiProvider::Vllm => write!(f, "vllm"),
            AiProvider::Huggingface => write!(f, "huggingface"),
            AiProvider::Nvidia => write!(f, "nvidia"),
            AiProvider::Sglang => write!(f, "sglang"),
            AiProvider::Litellm => write!(f, "litellm"),
            AiProvider::Portkey => write!(f, "portkey"),
            AiProvider::Helicone => write!(f, "helicone"),
            AiProvider::Langfuse => write!(f, "langfuse"),
            AiProvider::Mlflow => write!(f, "mlflow"),
            AiProvider::Arize => write!(f, "arize"),
            AiProvider::Other(s) => write!(f, "{s}"),
        }
    }
}

impl From<&str> for AiProvider {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "openai" => AiProvider::Openai,
            "anthropic" => AiProvider::Anthropic,
            "google" => AiProvider::Google,
            "azure" => AiProvider::Azure,
            "cohere" => AiProvider::Cohere,
            "mistral" => AiProvider::Mistral,
            "groq" => AiProvider::Groq,
            "together" => AiProvider::Together,
            "fireworks" => AiProvider::Fireworks,
            "deepseek" => AiProvider::Deepseek,
            "xai" => AiProvider::Xai,
            "aws" => AiProvider::Aws,
            "perplexity" => AiProvider::Perplexity,
            "openrouter" => AiProvider::Openrouter,
            "cloudflare" => AiProvider::Cloudflare,
            "kong" => AiProvider::Kong,
            "vllm" => AiProvider::Vllm,
            "huggingface" => AiProvider::Huggingface,
            "nvidia" => AiProvider::Nvidia,
            "sglang" => AiProvider::Sglang,
            "litellm" => AiProvider::Litellm,
            "portkey" => AiProvider::Portkey,
            "helicone" => AiProvider::Helicone,
            "langfuse" => AiProvider::Langfuse,
            "mlflow" => AiProvider::Mlflow,
            "arize" => AiProvider::Arize,
            _ => AiProvider::Other(s.to_string()),
        }
    }
}

/// SHA-256 digest value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn compute(data: &[u8]) -> Self {
        let hash = Sha256::digest(data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Sha256Digest(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// AI Traffic Record — complete LLM request/response pair.
#[derive(Debug, Clone)]
pub struct AiTrafficRecord {
    pub session_id: SessionId,
    pub provider: AiProvider,
    pub model_name: String,
    pub endpoint_path: String,

    pub prompt_text_hash: Sha256Digest,
    pub prompt_char_count: u32,
    pub prompt_token_count: u32,
    pub system_prompt_hash: Option<Sha256Digest>,
    pub tool_def_count: u8,
    pub tools_total_chars: u32,

    pub response_total_tokens: u32,
    pub completion_tokens: u32,
    pub reasoning_tokens: u32,
    pub tool_call_tokens: u32,
    pub first_token_latency_ms: u32,
    pub inter_token_avg_ms: f32,
    pub inter_token_p50_ms: f32,
    pub inter_token_p95_ms: f32,
    pub inter_token_p99_ms: f32,
    pub tokens_per_second: f32,
    pub total_stream_duration_ms: u32,

    pub tcp_handshake_ms: u32,
    pub tls_handshake_ms: u32,
    pub tls_psk_resumption: bool,
    pub server_processing_ms: u32,
    pub finish_reason: String,
    pub error_type: Option<String>,
    pub http_status: u16,
    pub retry_count: u8,

    pub prompt_cost_usd: f64,
    pub completion_cost_usd: f64,
    pub total_cost_usd: f64,
    pub cost_per_1k_input: f64,
    pub cost_per_1k_output: f64,

    pub timestamp_start: DateTime<Utc>,
    pub timestamp_first_token: Option<DateTime<Utc>>,
    pub timestamp_end: Option<DateTime<Utc>>,
    pub geo_region: Option<String>,
}

impl AiTrafficRecord {
    pub fn duration_ms(&self) -> u64 {
        let end = self.timestamp_end.unwrap_or_else(Utc::now);
        (end - self.timestamp_start)
            .to_std()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn ttft_ms(&self) -> u32 {
        self.first_token_latency_ms
    }

    pub fn is_streaming(&self) -> bool {
        self.total_stream_duration_ms > 0
    }
}

/// Internal state for an active (in-progress) LLM session.
#[derive(Debug, Clone)]
struct ActiveSession {
    session_id: SessionId,
    provider: AiProvider,
    model_name: String,
    endpoint_path: String,

    prompt_text_hash: Sha256Digest,
    prompt_char_count: u32,
    prompt_token_count: u32,
    system_prompt_hash: Option<Sha256Digest>,
    tool_def_count: u8,
    tools_total_chars: u32,

    accumulated_completion_tokens: u32,
    accumulated_reasoning_tokens: u32,
    accumulated_tool_call_tokens: u32,
    accumulated_total_tokens: u32,
    accumulated_cost: f64,
    finish_reason: Option<String>,  // completed when set
    error_type: Option<String>,

    packet_timestamps: Vec<DateTime<Utc>>,
    first_chunk_time: Option<DateTime<Utc>>,
    last_chunk_time: Option<DateTime<Utc>>,

    http_status: u16,
    retry_count: u8,
    geo_region: Option<String>,

    timestamp_start: DateTime<Utc>,
}

impl ActiveSession {
    fn new(
    session_id: SessionId,
        meta: &LlmMetadata,
        payload: &[u8],
        timestamp: DateTime<Utc>,
        _src_ip: IpAddr,
        _dst_ip: IpAddr,
    ) -> Self {
        let hash = Sha256Digest::compute(payload);
        ActiveSession {
            session_id,
            provider: AiProvider::from(meta.provider.as_str()),
            model_name: meta.model.clone(),
            endpoint_path: String::new(),

            prompt_text_hash: hash,
            prompt_char_count: payload.len() as u32,
            prompt_token_count: meta.prompt_tokens.unwrap_or(0) as u32,
            system_prompt_hash: None,
            tool_def_count: 0,
            tools_total_chars: 0,

            accumulated_completion_tokens: meta.completion_tokens.unwrap_or(0) as u32,
            accumulated_reasoning_tokens: 0,
            accumulated_tool_call_tokens: 0,
            accumulated_total_tokens: meta.total_tokens.unwrap_or(0) as u32,
            accumulated_cost: meta.cost_usd.unwrap_or(0.0),
            finish_reason: meta.finish_reason.clone(),
            error_type: meta.error_type.clone(),

            packet_timestamps: vec![timestamp],
            first_chunk_time: if meta.completion_tokens.is_some() || meta.finish_reason.is_some() {
                Some(timestamp)
            } else {
                None
            },
            last_chunk_time: None,

            http_status: 200,
            retry_count: 0,
            geo_region: None,

            timestamp_start: timestamp,
        }
    }

    fn record_chunk(&mut self, meta: &LlmMetadata, timestamp: DateTime<Utc>, _payload: &[u8]) {
        if let Some(ct) = meta.completion_tokens {
            self.accumulated_completion_tokens += ct as u32;
        }
        if let Some(tt) = meta.total_tokens {
            self.accumulated_total_tokens = tt as u32;
        }
        if meta.finish_reason.is_some() {
            self.finish_reason = meta.finish_reason.clone();
        }
        if meta.error_type.is_some() {
            self.error_type = meta.error_type.clone();
        }
        if let Some(cost) = meta.cost_usd {
            self.accumulated_cost += cost;
        }
        if meta.model != self.model_name && !meta.model.is_empty() {
            self.model_name = meta.model.clone();
        }
        if self.first_chunk_time.is_none() {
            self.first_chunk_time = Some(timestamp);
        }
        self.last_chunk_time = Some(timestamp);
        self.packet_timestamps.push(timestamp);
    }

    fn is_complete(&self) -> bool {
        self.finish_reason.is_some() || self.error_type.is_some()
    }

    fn into_record(self) -> AiTrafficRecord {
        let total_stream = match (self.first_chunk_time, self.last_chunk_time) {
            (Some(first), Some(last)) => {
                (last - first).to_std().map(|d| d.as_millis() as u32).unwrap_or(0)
            }
            _ => 0,
        };
        let ttft = match (self.timestamp_start, self.first_chunk_time) {
            (start, Some(first)) => {
                (first - start).to_std().map(|d| d.as_millis() as u32).unwrap_or(0)
            }
            _ => 0,
        };
        let _token_count = self.packet_timestamps.len().saturating_sub(1).max(1) as f32;
        let tokens_per_sec = if total_stream > 0 {
            self.accumulated_completion_tokens as f32 / (total_stream as f32 / 1000.0)
        } else {
            0.0
        };
        let inter_token_delays: Vec<f64> = self
            .packet_timestamps
            .windows(2)
            .filter_map(|w| (w[1] - w[0]).to_std().ok().map(|d| d.as_secs_f64() * 1000.0))
            .collect();
        let (avg, p50, p95, p99) = compute_latency_percentiles(&inter_token_delays);

        AiTrafficRecord {
            session_id: self.session_id,
            provider: self.provider,
            model_name: self.model_name,
            endpoint_path: self.endpoint_path,

            prompt_text_hash: self.prompt_text_hash,
            prompt_char_count: self.prompt_char_count,
            prompt_token_count: self.prompt_token_count,
            system_prompt_hash: self.system_prompt_hash,
            tool_def_count: self.tool_def_count,
            tools_total_chars: self.tools_total_chars,

            response_total_tokens: self.accumulated_total_tokens,
            completion_tokens: self.accumulated_completion_tokens,
            reasoning_tokens: self.accumulated_reasoning_tokens,
            tool_call_tokens: self.accumulated_tool_call_tokens,
            first_token_latency_ms: ttft,
            inter_token_avg_ms: avg as f32,
            inter_token_p50_ms: p50 as f32,
            inter_token_p95_ms: p95 as f32,
            inter_token_p99_ms: p99 as f32,
            tokens_per_second: tokens_per_sec,
            total_stream_duration_ms: total_stream,

            tcp_handshake_ms: 0,
            tls_handshake_ms: 0,
            tls_psk_resumption: false,
            server_processing_ms: ttft,
            finish_reason: self.finish_reason.clone().unwrap_or_default(),
            error_type: self.error_type.clone(),
            http_status: self.http_status,
            retry_count: self.retry_count,

            prompt_cost_usd: self.accumulated_cost,
            completion_cost_usd: 0.0,
            total_cost_usd: self.accumulated_cost,
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,

            timestamp_start: self.timestamp_start,
            timestamp_first_token: self.first_chunk_time,
            timestamp_end: self.last_chunk_time,
            geo_region: self.geo_region,
        }
    }
}

fn compute_latency_percentiles(delays: &[f64]) -> (f64, f64, f64, f64) {
    if delays.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let mut sorted = delays.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let len = sorted.len();
    let avg = sorted.iter().sum::<f64>() / len as f64;
    let p50 = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let p99 = percentile(&sorted, 0.99);
    (avg, p50, p95, p99)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Tracks active LLM sessions across packets, producing complete records.
#[derive(Debug, Clone)]
pub struct AiTrafficTracker {
    sessions: HashMap<(IpAddr, u16, IpAddr, u16), ActiveSession>,
    completed: Vec<AiTrafficRecord>,
    next_retry: HashMap<(IpAddr, u16, IpAddr, u16), u8>,
}

impl Default for AiTrafficTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AiTrafficTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            completed: Vec::new(),
            next_retry: HashMap::new(),
        }
    }

    pub fn record_packet(
        &mut self,
        meta: &LlmMetadata,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        let key = (src_ip, src_port, dst_ip, dst_port);
        let session = self.sessions.get_mut(&key);
        match session {
            Some(s) => {
                s.record_chunk(meta, timestamp, payload);
                if s.is_complete() {
                    if let Some(s) = self.sessions.remove(&key) {
                        let mut record = s.into_record();
                        if let Some(&retries) = self.next_retry.get(&key) {
                            record.retry_count = retries;
                            self.next_retry.remove(&key);
                        }
                        self.completed.push(record);
                    }
                }
            }
            None => {
                if meta.request_type == "moderation"
                    || meta.request_type == "observability"
                {
                    return;
                }
                let session = ActiveSession::new(
                    next_session_id(),
                    meta,
                    payload,
                    timestamp,
                    src_ip,
                    dst_ip,
                );
                if session.is_complete() {
                    let mut record = session.into_record();
                    if let Some(&retries) = self.next_retry.get(&key) {
                        record.retry_count = retries;
                        self.next_retry.remove(&key);
                    }
                    self.completed.push(record);
                } else {
                    self.sessions.insert(key, session);
                }
            }
        }
    }

    pub fn record_retry(&mut self, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) {
        let key = (src_ip, src_port, dst_ip, dst_port);
        *self.next_retry.entry(key).or_insert(0) += 1;
    }

    pub fn completed_records(&self) -> &[AiTrafficRecord] {
        &self.completed
    }

    pub fn drain_completed(&mut self) -> Vec<AiTrafficRecord> {
        std::mem::take(&mut self.completed)
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_completed(&self) -> usize {
        self.completed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_analytics::LlmMetadata;

    fn sample_meta(model: &str, provider: &str, finish: Option<&str>, ct: Option<u64>, tt: Option<u64>) -> LlmMetadata {
        LlmMetadata {
            provider: provider.into(),
            model: model.into(),
            model_family: String::new(),
            prompt_tokens: Some(50),
            completion_tokens: ct,
            total_tokens: tt,
            finish_reason: finish.map(String::from),
            request_type: "chat".into(),
            streaming: true,
            error_type: None,
            tool_calls: false,
            cost_usd: Some(0.001),
            latency_ms: None,
        }
    }

    #[test]
    fn test_ai_provider_from_str() {
        assert_eq!(AiProvider::from("openai"), AiProvider::Openai);
        assert_eq!(AiProvider::from("anthropic"), AiProvider::Anthropic);
        assert_eq!(AiProvider::from("unknown"), AiProvider::Other("unknown".into()));
    }

    #[test]
    fn test_ai_provider_display() {
        assert_eq!(AiProvider::Openai.to_string(), "openai");
        assert_eq!(AiProvider::Anthropic.to_string(), "anthropic");
        assert_eq!(AiProvider::Other("custom".into()).to_string(), "custom");
    }

    #[test]
    fn test_sha256_digest() {
        let d1 = Sha256Digest::compute(b"hello");
        let d2 = Sha256Digest::compute(b"hello");
        let d3 = Sha256Digest::compute(b"world");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
        assert_eq!(d1.to_string().len(), 64);
    }

    #[test]
    fn test_tracker_completes_session() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta1 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta1, ip1, 50000, ip2, 443, b"prompt data", now);
        assert_eq!(tracker.active_session_count(), 1);
        assert_eq!(tracker.total_completed(), 0);

        let meta2 = sample_meta("gpt-4", "openai", Some("stop"), Some(50), Some(100));
        tracker.record_packet(
            &meta2, ip1, 50000, ip2, 443,
            b"response data", now + Duration::from_millis(200),
        );
        assert_eq!(tracker.active_session_count(), 0);
        assert_eq!(tracker.total_completed(), 1);
    }

    #[test]
    fn test_tracker_multiple_sessions() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta1 = sample_meta("claude-3", "anthropic", Some("stop"), Some(30), Some(80));
        tracker.record_packet(&meta1, ip1, 50001, ip2, 443, b"req1", now);
        assert_eq!(tracker.total_completed(), 1);

        let meta2 = sample_meta("gemini-pro", "google", Some("stop"), Some(20), Some(70));
        tracker.record_packet(&meta2, ip1, 50002, ip2, 443, b"req2", now + Duration::from_millis(10));
        assert_eq!(tracker.total_completed(), 2);
    }

    #[test]
    fn test_tracker_retry_counting() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let mut tracker = AiTrafficTracker::new();

        tracker.record_retry(ip1, 50000, ip2, 443);
        tracker.record_retry(ip1, 50000, ip2, 443);
        assert_eq!(tracker.active_session_count(), 0);
        assert_eq!(tracker.total_completed(), 0);

        let now = Utc::now();
        let meta = sample_meta("gpt-4", "openai", Some("stop"), Some(10), Some(20));
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"req", now);
        assert_eq!(tracker.total_completed(), 1);
        assert_eq!(tracker.completed_records()[0].retry_count, 2);
    }

    #[test]
    fn test_drain_completed() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = sample_meta("gpt-4", "openai", Some("stop"), Some(10), Some(20));
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"data", now);
        assert_eq!(tracker.drain_completed().len(), 1);
        assert_eq!(tracker.total_completed(), 0);
    }

    #[test]
    fn test_ttft_calculation() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta1 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta1, ip1, 50000, ip2, 443, b"prompt", now);

        let meta2 = sample_meta("gpt-4", "openai", Some("stop"), Some(50), Some(100));
        tracker.record_packet(
            &meta2, ip1, 50000, ip2, 443, b"chunk",
            now + Duration::from_millis(350),
        );
        let record = &tracker.completed_records()[0];
        assert_eq!(record.first_token_latency_ms, 350);
        assert!(record.server_processing_ms > 0);
    }

    #[test]
    fn test_inter_token_percentiles() {
        let delays = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0];
        let (avg, p50, p95, _p99) = compute_latency_percentiles(&delays);
        assert!((avg - 55.0).abs() < 0.1);
        assert!(p50 > 0.0);
        assert!(p95 > 0.0);
    }

    #[test]
    fn test_empty_percentiles() {
        let (avg, p50, p95, p99) = compute_latency_percentiles(&[]);
        assert_eq!(avg, 0.0);
        assert_eq!(p50, 0.0);
        assert_eq!(p95, 0.0);
        assert_eq!(p99, 0.0);
    }

    #[test]
    fn test_session_ttft_via_packet_timing() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta1 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta1, ip1, 50000, ip2, 443, b"req", now);

        let meta2 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta2, ip1, 50000, ip2, 443, b"chunk1", now + Duration::from_millis(100));

        let meta3 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta3, ip1, 50000, ip2, 443, b"chunk2", now + Duration::from_millis(200));

        let meta4 = sample_meta("gpt-4", "openai", Some("stop"), Some(30), Some(80));
        tracker.record_packet(&meta4, ip1, 50000, ip2, 443, b"final", now + Duration::from_millis(500));

        let record = &tracker.completed_records()[0];
        assert_eq!(record.ttft_ms(), 100);
        assert_eq!(record.total_stream_duration_ms, 400);
        assert!(record.completion_tokens >= 30);
    }

    #[test]
    fn test_active_session_count() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta, ip1, 50001, ip2, 443, b"session1", now);
        tracker.record_packet(&meta, ip1, 50002, ip2, 443, b"session2", now);
        assert_eq!(tracker.active_session_count(), 2);
    }

    #[test]
    fn test_moderation_not_tracked() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = LlmMetadata {
            provider: "openai".into(),
            model: "text-moderation".into(),
            model_family: String::new(),
            prompt_tokens: Some(10),
            completion_tokens: None,
            total_tokens: None,
            finish_reason: None,
            request_type: "moderation".into(),
            streaming: false,
            error_type: None,
            tool_calls: false,
            cost_usd: None,
            latency_ms: None,
        };
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"mod", now);
        assert_eq!(tracker.active_session_count(), 0);
    }

    #[test]
    fn test_observability_not_tracked() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = LlmMetadata {
            provider: "langfuse".into(),
            model: "langfuse".into(),
            model_family: String::new(),
            prompt_tokens: Some(5),
            completion_tokens: None,
            total_tokens: None,
            finish_reason: None,
            request_type: "observability".into(),
            streaming: false,
            error_type: None,
            tool_calls: false,
            cost_usd: None,
            latency_ms: None,
        };
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"obs", now);
        assert_eq!(tracker.active_session_count(), 0);
        assert_eq!(tracker.total_completed(), 0);
    }

    #[test]
    fn test_finish_reason_in_record() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = sample_meta("gpt-4", "openai", Some("length"), Some(20), Some(70));
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"req", now);
        let record = &tracker.completed_records()[0];
        assert_eq!(record.finish_reason, "length");
    }

    #[test]
    fn test_error_type_in_record() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = LlmMetadata {
            provider: "openai".into(),
            model: "gpt-4".into(),
            model_family: String::new(),
            prompt_tokens: Some(50),
            completion_tokens: None,
            total_tokens: None,
            finish_reason: Some("error".into()),
            request_type: "chat".into(),
            streaming: false,
            error_type: Some("rate_limit_exceeded".into()),
            tool_calls: false,
            cost_usd: Some(0.0),
            latency_ms: None,
        };
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"err", now);
        let record = &tracker.completed_records()[0];
        assert_eq!(record.finish_reason, "error");
        assert_eq!(record.error_type, Some("rate_limit_exceeded".into()));
    }

    #[test]
    fn test_completion_tokens_accumulate_across_chunks() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta1 = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&meta1, ip1, 50000, ip2, 443, b"req", now);

        let chunk1 = sample_meta("gpt-4", "openai", None, Some(10), Some(10));
        tracker.record_packet(&chunk1, ip1, 50000, ip2, 443, b"chunk1", now + Duration::from_millis(100));

        let chunk2 = sample_meta("gpt-4", "openai", None, Some(15), Some(15));
        tracker.record_packet(&chunk2, ip1, 50000, ip2, 443, b"chunk2", now + Duration::from_millis(200));

        let final_meta = sample_meta("gpt-4", "openai", Some("stop"), Some(25), Some(75));
        tracker.record_packet(&final_meta, ip1, 50000, ip2, 443, b"final", now + Duration::from_millis(500));

        let record = &tracker.completed_records()[0];
        assert_eq!(record.completion_tokens, 50);
        assert_eq!(record.prompt_token_count, 50);
    }

    #[test]
    fn test_retry_transfer_on_chunked_session() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        tracker.record_retry(ip1, 50000, ip2, 443);
        tracker.record_retry(ip1, 50000, ip2, 443);

        let req = sample_meta("gpt-4", "openai", None, None, None);
        tracker.record_packet(&req, ip1, 50000, ip2, 443, b"req", now);

        let resp = sample_meta("gpt-4", "openai", Some("stop"), Some(10), Some(60));
        tracker.record_packet(&resp, ip1, 50000, ip2, 443, b"resp", now + Duration::from_millis(200));

        let record = &tracker.completed_records()[0];
        assert_eq!(record.retry_count, 2);
    }

    #[test]
    fn test_drain_clears_completed() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Utc::now();
        let mut tracker = AiTrafficTracker::new();

        let meta = sample_meta("gpt-4", "openai", Some("stop"), Some(10), Some(60));
        tracker.record_packet(&meta, ip1, 50000, ip2, 443, b"data", now);
        assert_eq!(tracker.drain_completed().len(), 1);
        assert_eq!(tracker.drain_completed().len(), 0);
    }
}
