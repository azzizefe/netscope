use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Utc};

use crate::models::Protocol;

/// LLM-specific metadata extracted from an LLM API packet.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmMetadata {
    pub provider: String,
    pub model: String,
    pub model_family: String,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub finish_reason: Option<String>,
    pub request_type: String,
    pub streaming: bool,
    pub error_type: Option<String>,
    pub tool_calls: bool,
    pub cost_usd: Option<f64>,
    pub latency_ms: Option<u64>,
}

/// Extract LLM metadata from a raw frame payload and its dissected protocol.
pub fn extract_llm_metadata(payload: &[u8], protocol: &Protocol) -> Option<LlmMetadata> {
    if !is_llm_protocol(protocol) {
        return None;
    }
    let cow = String::from_utf8_lossy(payload);
    let raw = strip_sse_prefix(&cow);
    let provider = provider_from_protocol(protocol);
    let model = extract_model(raw, &provider);
    let model_family = classify_model_family(&model);
    let prompt_tokens = extract_prompt_tokens(raw, &provider);
    let completion_tokens = extract_completion_tokens(raw, &provider);
    let total_tokens = extract_total_tokens(raw, &provider);
    let finish_reason = extract_finish_reason(raw, &provider);
    let request_type = request_type_from_protocol(protocol);
    let streaming = is_streaming_protocol(protocol);
    let error_type = extract_error(raw, &provider);
    let tool_calls = raw.contains("\"tool_calls\"") || raw.contains("tool_call_id");
    let cost_usd = estimate_cost(&provider, &model, prompt_tokens, completion_tokens);
    let latency_ms = None;
    Some(LlmMetadata {
        provider,
        model,
        model_family,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        finish_reason,
        request_type,
        streaming,
        error_type,
        tool_calls,
        cost_usd,
        latency_ms,
    })
}

fn is_llm_protocol(p: &Protocol) -> bool {
    matches!(
        p,
        Protocol::OpenaiChatStream
            | Protocol::OpenaiRealtimeWs
            | Protocol::OpenaiResponsesApi
            | Protocol::AnthropicStreamEvt
            | Protocol::GoogleGeminiBidi
            | Protocol::GoogleGeminiRestStream
            | Protocol::AzureAoaiStream
            | Protocol::CohereStreamV2
            | Protocol::MistralChatStream
            | Protocol::GroqLpcuStream
            | Protocol::TogetherStream
            | Protocol::FireworksStream
            | Protocol::DeepseekStream
            | Protocol::XaiGrokStream
            | Protocol::BedrockInvokeStream
            | Protocol::LitellmProxyStream
            | Protocol::PortkeyStreamRelay
            | Protocol::HeliconeLogStream
            | Protocol::LangfuseIngestV2
            | Protocol::MlflowGatewayStream
            | Protocol::OpenrouterStream
            | Protocol::CloudflareAiGateway
            | Protocol::KongAiGatewayStream
            | Protocol::VllmAsyncEngine
            | Protocol::TgiMessages
            | Protocol::TritonInferenceGrpc
            | Protocol::TritonModelRepoStream
            | Protocol::SglangRadixCache
            | Protocol::OpenllmetryOtlp
            | Protocol::ArizePhoenixCollect
            | Protocol::LangfuseIngest
            | Protocol::HeliconeWorkerQueue
            | Protocol::LiteserveGrpc
            | Protocol::MlflowGateway
            | Protocol::PortkeyGatewayRouter
            | Protocol::OpenaiRealtime
            | Protocol::OpenaiBatchApi
            | Protocol::OpenaiStreamingSse
            | Protocol::AnthropicMessagesStream
            | Protocol::AnthropicToolUseBridge
            | Protocol::GoogleGeminiStream
            | Protocol::GoogleAistudioWs
            | Protocol::AegisGuardLlama
            | Protocol::AnthropicConstitutional
            | Protocol::AzureAiContentSafety
            | Protocol::GuardrailsAiValidator
            | Protocol::LlamaGuardSafeguard
            | Protocol::NemoGuardrailsHttp
            | Protocol::OpenaiModerationAsync
    )
}

fn is_streaming_protocol(p: &Protocol) -> bool {
    matches!(
        p,
        Protocol::OpenaiChatStream
            | Protocol::OpenaiRealtimeWs
            | Protocol::OpenaiResponsesApi
            | Protocol::AnthropicStreamEvt
            | Protocol::GoogleGeminiBidi
            | Protocol::GoogleGeminiRestStream
            | Protocol::AzureAoaiStream
            | Protocol::CohereStreamV2
            | Protocol::MistralChatStream
            | Protocol::GroqLpcuStream
            | Protocol::TogetherStream
            | Protocol::FireworksStream
            | Protocol::DeepseekStream
            | Protocol::XaiGrokStream
            | Protocol::BedrockInvokeStream
            | Protocol::LitellmProxyStream
            | Protocol::PortkeyStreamRelay
            | Protocol::MlflowGatewayStream
            | Protocol::OpenrouterStream
            | Protocol::CloudflareAiGateway
            | Protocol::KongAiGatewayStream
            | Protocol::VllmAsyncEngine
            | Protocol::TgiMessages
            | Protocol::TritonModelRepoStream
            | Protocol::SglangRadixCache
            | Protocol::GoogleGeminiStream
            | Protocol::GoogleAistudioWs
            | Protocol::OpenaiStreamingSse
            | Protocol::OpenaiRealtime
    )
}

fn provider_from_protocol(p: &Protocol) -> String {
    match p {
        Protocol::OpenaiChatStream
        | Protocol::OpenaiRealtimeWs
        | Protocol::OpenaiResponsesApi
        | Protocol::OpenaiRealtime
        | Protocol::OpenaiBatchApi
        | Protocol::OpenaiStreamingSse
        | Protocol::OpenaiModerationAsync => "openai".into(),
        Protocol::AnthropicStreamEvt
        | Protocol::AnthropicMessagesStream
        | Protocol::AnthropicToolUseBridge
        | Protocol::AnthropicConstitutional => "anthropic".into(),
        Protocol::GoogleGeminiBidi
        | Protocol::GoogleGeminiRestStream
        | Protocol::GoogleGeminiStream
        | Protocol::GoogleAistudioWs => "google".into(),
        Protocol::AzureAoaiStream | Protocol::AzureAiContentSafety => "azure".into(),
        Protocol::CohereStreamV2 => "cohere".into(),
        Protocol::MistralChatStream => "mistral".into(),
        Protocol::GroqLpcuStream => "groq".into(),
        Protocol::TogetherStream => "together".into(),
        Protocol::FireworksStream => "fireworks".into(),
        Protocol::DeepseekStream => "deepseek".into(),
        Protocol::XaiGrokStream => "xai".into(),
        Protocol::BedrockInvokeStream => "aws".into(),
        Protocol::LitellmProxyStream => "litellm".into(),
        Protocol::PortkeyStreamRelay | Protocol::PortkeyGatewayRouter => "portkey".into(),
        Protocol::HeliconeLogStream | Protocol::HeliconeWorkerQueue => "helicone".into(),
        Protocol::LangfuseIngestV2 | Protocol::LangfuseIngest => "langfuse".into(),
        Protocol::MlflowGatewayStream | Protocol::MlflowGateway => "mlflow".into(),
        Protocol::OpenrouterStream => "openrouter".into(),
        Protocol::CloudflareAiGateway => "cloudflare".into(),
        Protocol::KongAiGatewayStream => "kong".into(),
        Protocol::VllmAsyncEngine => "vllm".into(),
        Protocol::TgiMessages => "huggingface".into(),
        Protocol::TritonInferenceGrpc | Protocol::TritonModelRepoStream => "nvidia".into(),
        Protocol::SglangRadixCache => "sglang".into(),
        Protocol::OpenllmetryOtlp => "openllmetry".into(),
        Protocol::ArizePhoenixCollect => "arize".into(),
        Protocol::LiteserveGrpc => "liteserve".into(),
        Protocol::AegisGuardLlama
        | Protocol::LlamaGuardSafeguard
        | Protocol::NemoGuardrailsHttp => "guardrails".into(),
        Protocol::GuardrailsAiValidator => "guardrails".into(),
        _ => "unknown".into(),
    }
}

fn request_type_from_protocol(p: &Protocol) -> String {
    match p {
        Protocol::OpenaiChatStream
        | Protocol::OpenaiResponsesApi
        | Protocol::AnthropicStreamEvt
        | Protocol::AnthropicMessagesStream
        | Protocol::GoogleGeminiRestStream
        | Protocol::AzureAoaiStream
        | Protocol::CohereStreamV2
        | Protocol::MistralChatStream
        | Protocol::GroqLpcuStream
        | Protocol::TogetherStream
        | Protocol::FireworksStream
        | Protocol::DeepseekStream
        | Protocol::XaiGrokStream
        | Protocol::BedrockInvokeStream
        | Protocol::LitellmProxyStream
        | Protocol::PortkeyStreamRelay
        | Protocol::MlflowGatewayStream
        | Protocol::OpenrouterStream
        | Protocol::CloudflareAiGateway
        | Protocol::KongAiGatewayStream
        | Protocol::VllmAsyncEngine
        | Protocol::TgiMessages
        | Protocol::TritonModelRepoStream
        | Protocol::SglangRadixCache
        | Protocol::GoogleGeminiStream
        | Protocol::OpenaiStreamingSse
        | Protocol::HeliconeWorkerQueue
        | Protocol::PortkeyGatewayRouter
        | Protocol::LiteserveGrpc
        | Protocol::MlflowGateway => "chat".into(),
        Protocol::OpenaiRealtimeWs | Protocol::OpenaiRealtime | Protocol::GoogleGeminiBidi => {
            "realtime".into()
        }
        Protocol::OpenaiBatchApi => "batch".into(),
        Protocol::OpenaiModerationAsync
        | Protocol::AzureAiContentSafety
        | Protocol::GuardrailsAiValidator
        | Protocol::AegisGuardLlama
        | Protocol::AnthropicConstitutional
        | Protocol::LlamaGuardSafeguard
        | Protocol::NemoGuardrailsHttp => "moderation".into(),
        Protocol::AnthropicToolUseBridge => "tool_use".into(),
        Protocol::GoogleAistudioWs => "studio".into(),
        Protocol::TritonInferenceGrpc | Protocol::OpenllmetryOtlp => "inference".into(),
        Protocol::LangfuseIngestV2 | Protocol::LangfuseIngest => "observability".into(),
        Protocol::HeliconeLogStream | Protocol::ArizePhoenixCollect => "observability".into(),
        _ => "unknown".into(),
    }
}

fn strip_sse_prefix(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix("data: ") {
        rest.trim()
    } else if let Some(rest) = raw.strip_prefix("event: ") {
        rest.trim()
    } else {
        raw
    }
}

fn extract_model(raw: &str, provider: &str) -> String {
    if provider == "anthropic" {
        if let Some(m) = extract_json_field(raw, "model") {
            return m;
        }
    }
    if let Some(m) = extract_nested_json_field(raw, "model") {
        if !m.is_empty() {
            return m;
        }
    }
    if provider == "google" {
        if let Some(m) = extract_json_field(raw, "modelVersion") {
            return m;
        }
    }
    String::new()
}

pub fn classify_model_family(model: &str) -> String {
    let m = model.to_lowercase();
    if m.contains("gpt-4") || m.contains("gpt4") {
        "gpt-4".into()
    } else if m.contains("gpt-3.5") || m.contains("gpt-35") {
        "gpt-3.5".into()
    } else if m.contains("o1") || m.contains("o3") {
        "o-series".into()
    } else if m.contains("claude-3") || m.contains("claude3") {
        "claude-3".into()
    } else if m.contains("claude-2") || m.contains("claude2") {
        "claude-2".into()
    } else if m.contains("claude") {
        "claude".into()
    } else if m.contains("gemini-2.0") || m.contains("gemini2.0") {
        "gemini-2.0".into()
    } else if m.contains("gemini-1.5") || m.contains("gemini1.5") {
        "gemini-1.5".into()
    } else if m.contains("gemini-1.0") || m.contains("gemini1.0") || m.contains("gemini-pro") {
        "gemini-1.0".into()
    } else if m.contains("gemini") {
        "gemini".into()
    } else if m.contains("llama-3") || m.contains("llama3") {
        "llama-3".into()
    } else if m.contains("llama-2") || m.contains("llama2") {
        "llama-2".into()
    } else if m.contains("llama") {
        "llama".into()
    } else if m.contains("mistral-large") || m.contains("mistral_large") {
        "mistral-large".into()
    } else if m.contains("mistral-medium") || m.contains("mistral_medium") {
        "mistral-medium".into()
    } else if m.contains("mistral-small") || m.contains("mistral_small") {
        "mistral-small".into()
    } else if m.contains("mistral") {
        "mistral".into()
    } else if m.contains("mixtral") {
        "mixtral".into()
    } else if m.contains("command-r") || m.contains("command_r") {
        "command-r".into()
    } else if m.contains("command") {
        "command".into()
    } else if m.contains("deepseek") {
        "deepseek".into()
    } else if m.contains("grok") {
        "grok".into()
    } else if m.contains("dbrx") || m.contains("dbrix") {
        "dbrx".into()
    } else if m.contains("phi-3") || m.contains("phi3") || m.contains("phi-4") || m.contains("phi4")
    {
        "phi".into()
    } else if m.contains("qwen") {
        "qwen".into()
    } else if m.contains("yi-") || m.contains("yi/") {
        "yi".into()
    } else if m.contains("gemma") {
        "gemma".into()
    } else if m.contains("falcon") {
        "falcon".into()
    } else if m.contains("bert") {
        "bert".into()
    } else if m.contains("t5-") || m.contains("t5_") || m.contains("flan-t5") {
        "t5".into()
    } else {
        String::new()
    }
}

fn extract_prompt_tokens(raw: &str, provider: &str) -> Option<u64> {
    if provider == "anthropic" {
        extract_json_number(raw, "input_tokens")
            .or_else(|| extract_nested_json_number(raw, "input_tokens"))
    } else {
        extract_json_number(raw, "prompt_tokens")
            .or_else(|| extract_nested_json_number(raw, "prompt_tokens"))
            .or_else(|| extract_nested_json_number(raw, "input_tokens"))
    }
}

fn extract_completion_tokens(raw: &str, provider: &str) -> Option<u64> {
    if provider == "anthropic" {
        extract_json_number(raw, "output_tokens")
            .or_else(|| extract_nested_json_number(raw, "output_tokens"))
    } else {
        extract_json_number(raw, "completion_tokens")
            .or_else(|| extract_nested_json_number(raw, "completion_tokens"))
            .or_else(|| extract_nested_json_number(raw, "output_tokens"))
    }
}

fn extract_total_tokens(raw: &str, _provider: &str) -> Option<u64> {
    extract_json_number(raw, "total_tokens")
        .or_else(|| extract_nested_json_number(raw, "total_tokens"))
}

fn extract_finish_reason(raw: &str, _provider: &str) -> Option<String> {
    extract_json_field(raw, "finish_reason")
        .or_else(|| extract_nested_json_field(raw, "finish_reason"))
}

fn extract_error(raw: &str, _provider: &str) -> Option<String> {
    if let Some(err) = extract_json_field(raw, "error") {
        return Some(err);
    }
    if raw.contains("\"error\"") && raw.contains("\"code\"") {
        if let Some(code) = extract_json_field(raw, "code") {
            return Some(code);
        }
    }
    if raw.contains("\"error\"") && raw.contains("\"type\"") {
        if let Some(err_type) = extract_json_field(raw, "type") {
            return Some(err_type);
        }
    }
    None
}

fn estimate_cost(
    provider: &str,
    model: &str,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
) -> Option<f64> {
    let (prompt_rate, completion_rate) = lookup_pricing(provider, model)?;
    let pt = prompt_tokens.unwrap_or(0) as f64;
    let ct = completion_tokens.unwrap_or(0) as f64;
    let cost = (pt * prompt_rate + ct * completion_rate) / 1_000_000.0;
    Some(cost)
}

fn lookup_pricing(provider: &str, model: &str) -> Option<(f64, f64)> {
    let m = model.to_lowercase();
    match (provider, classify_model_family(&m).as_str()) {
        ("openai", "gpt-4") if m.contains("turbo") => Some((10.0, 30.0)),
        ("openai", "gpt-4") if m.contains("32k") => Some((60.0, 120.0)),
        ("openai", "gpt-4") => Some((30.0, 60.0)),
        ("openai", "gpt-3.5") if m.contains("16k") => Some((3.0, 4.0)),
        ("openai", "gpt-3.5") => Some((0.50, 1.50)),
        ("openai", "o-series") if m.contains("mini") => Some((1.10, 4.40)),
        ("openai", "o-series") => Some((15.0, 60.0)),
        ("anthropic", "claude-3") if m.contains("sonnet") => Some((3.0, 15.0)),
        ("anthropic", "claude-3") if m.contains("haiku") => Some((0.25, 1.25)),
        ("anthropic", "claude-3") if m.contains("opus") => Some((15.0, 75.0)),
        ("anthropic", "claude-2") | ("anthropic", "claude") => Some((8.0, 24.0)),
        ("google", "gemini-2.0") if m.contains("flash") => Some((0.10, 0.40)),
        ("google", "gemini-1.5") if m.contains("pro") => Some((1.25, 5.0)),
        ("google", "gemini-1.5") if m.contains("flash") => Some((0.075, 0.30)),
        ("google", "gemini-1.0") => Some((0.50, 1.50)),
        ("mistral", "mistral-large") => Some((2.0, 6.0)),
        ("mistral", "mistral-medium") => Some((2.70, 8.10)),
        ("mistral", "mistral-small") | ("mistral", "mistral") => Some((1.0, 3.0)),
        ("mistral", "mixtral") => Some((0.60, 2.40)),
        ("cohere", "command-r") if m.contains("plus") => Some((3.0, 15.0)),
        ("cohere", "command-r") | ("cohere", "command") => Some((0.50, 1.50)),
        ("deepseek", _) => Some((0.14, 0.28)),
        ("xai", "grok") => Some((5.0, 15.0)),
        ("groq", _) => Some((0.0, 0.0)),
        ("together", _) => Some((0.0, 0.0)),
        ("fireworks", _) => Some((0.0, 0.0)),
        ("perplexity", "llama-3") => Some((0.60, 1.80)),
        _ if m.contains("llama-3") && m.contains("70b") => Some((0.59, 0.79)),
        _ if m.contains("llama-3") && m.contains("8b") => Some((0.06, 0.08)),
        _ if m.contains("llama-2") && m.contains("70b") => Some((0.70, 0.95)),
        _ if m.contains("llama-2") && m.contains("13b") => Some((0.20, 0.25)),
        _ if m.contains("llama") && m.contains("7b") => Some((0.15, 0.20)),
        _ if m.contains("mixtral") && m.contains("8x7b") => Some((0.30, 0.60)),
        _ if m.contains("dbrx") => Some((0.60, 2.40)),
        _ if m.contains("phi") && m.contains("medium") => Some((0.10, 0.10)),
        ("vllm", _) | ("huggingface", _) | ("nvidia", _) | ("sglang", _) | ("litellm", _) => {
            Some((0.0, 0.0))
        }
        _ => None,
    }
}

fn extract_json_field(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    if let Some(start) = raw.find(&pat) {
        let val_start = start + pat.len();
        let rest = &raw[val_start..];
        let mut end = 0;
        let mut escaped = false;
        for (i, c) in rest.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == '"' {
                end = i;
                break;
            }
        }
        if end > 0 {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn extract_nested_json_field(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    if raw.find(&pat).is_some() {
        for nested in [
            "usage",
            "response",
            "message",
            "choices[0]",
            "candidates[0]",
        ] {
            let nested_pat = format!("\"{}\":", nested);
            if let Some(n_start) = raw.find(&nested_pat) {
                let rest = &raw[n_start + nested_pat.len()..];
                if let Some(v) = extract_json_field(rest, key) {
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
        extract_json_field(raw, key)
    } else {
        None
    }
}

fn extract_json_number(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{}\":", key);
    if let Some(start) = raw.find(&pat) {
        let val_start = start + pat.len();
        let rest = &raw[val_start..];
        let trimmed = rest.trim_start();
        let num_str: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse::<u64>().ok()
    } else {
        None
    }
}

fn extract_nested_json_number(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{}\"", key);
    if raw.find(&pat).is_some() {
        for nested in [
            "usage",
            "response",
            "message",
            "choices[0]",
            "candidates[0]",
        ] {
            let nested_pat = format!("\"{}\":", nested);
            if let Some(n_start) = raw.find(&nested_pat) {
                let rest = &raw[n_start + nested_pat.len()..];
                if let Some(v) = extract_json_number(rest, key) {
                    return Some(v);
                }
            }
        }
        extract_json_number(raw, key)
    } else {
        None
    }
}

/// Session-level metrics computed from a completed LLM request/response pair.
/// Used to populate per-model statistics like TTFT, TPOT, tokens/s, etc.
#[derive(Debug, Clone)]
pub struct LlmSessionMetrics {
    pub model: String,
    pub provider: String,
    pub model_family: String,
    pub request_type: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub ttft_ms: u64,
    pub stream_duration_ms: u64,
    pub http_status: u16,
    pub streaming: bool,
    pub finish_reason: String,
    pub error_type: Option<String>,
    pub prompt_text: String,
    pub response_text: String,
}

/// Anomaly alert triggered when a metric threshold is exceeded.
#[derive(Debug, Clone)]
pub struct AnomalyAlert {
    pub model: String,
    pub metric: String,
    pub value: String,
    pub threshold: String,
    pub timestamp: DateTime<Utc>,
}

/// Aggregated LLM analytics across all recorded packets.
#[derive(Debug, Clone)]
pub struct LlmAnalytics {
    pub total_requests: u64,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub total_tokens: u64,
    pub total_cost: f64,
    pub streaming_requests: u64,
    pub non_streaming_requests: u64,
    pub total_errors: u64,
    pub per_model: HashMap<String, LlmModelStats>,
    pub per_provider: HashMap<String, LlmProviderStats>,
    pub per_model_family: HashMap<String, LlmModelFamilyStats>,
    pub per_request_type: HashMap<String, u64>,
    pub latency_buckets: [u64; 6],
    pub latency_heatmap: VecDeque<(DateTime<Utc>, String, u64)>,
    pub cost_timeline: VecDeque<(DateTime<Utc>, f64)>,
    pub session_cost: f64,
    pub daily_cost: f64,
    pub last_cost_reset: DateTime<Utc>,
    pub anomalies: VecDeque<AnomalyAlert>,
    pub max_heatmap_points: usize,
    pub max_anomalies: usize,
}

#[derive(Debug, Clone)]
pub struct LlmModelStats {
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub errors: u64,
    pub ttft_sum_ms: u64,
    pub ttft_count: u64,
    pub tpot_sum_us: u64,
    pub tpot_count: u64,
    pub tokens_per_second_sum: f64,
    pub tokens_per_second_count: u64,
    pub error_4xx: u64,
    pub error_5xx: u64,
    pub rate_limited: u64,
    pub incomplete_streams: u64,
    pub total_streams: u64,
}

#[derive(Debug, Clone)]
pub struct LlmProviderStats {
    pub requests: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct LlmModelFamilyStats {
    pub requests: u64,
    pub total_tokens: u64,
    pub cost: f64,
}

impl Default for LlmModelStats {
    fn default() -> Self {
        Self {
            requests: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            cost: 0.0,
            errors: 0,
            ttft_sum_ms: 0,
            ttft_count: 0,
            tpot_sum_us: 0,
            tpot_count: 0,
            tokens_per_second_sum: 0.0,
            tokens_per_second_count: 0,
            error_4xx: 0,
            error_5xx: 0,
            rate_limited: 0,
            incomplete_streams: 0,
            total_streams: 0,
        }
    }
}

impl Default for LlmAnalytics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            total_tokens: 0,
            total_cost: 0.0,
            streaming_requests: 0,
            non_streaming_requests: 0,
            total_errors: 0,
            per_model: HashMap::new(),
            per_provider: HashMap::new(),
            per_model_family: HashMap::new(),
            per_request_type: HashMap::new(),
            latency_buckets: [0; 6],
            latency_heatmap: VecDeque::with_capacity(1000),
            cost_timeline: VecDeque::with_capacity(10000),
            session_cost: 0.0,
            daily_cost: 0.0,
            last_cost_reset: Utc::now(),
            anomalies: VecDeque::with_capacity(100),
            max_heatmap_points: 1000,
            max_anomalies: 100,
        }
    }
}

impl LlmAnalytics {
    pub fn record(&mut self, meta: &LlmMetadata) {
        self.total_requests += 1;
        if meta.streaming {
            self.streaming_requests += 1;
        } else {
            self.non_streaming_requests += 1;
        }
        if meta.error_type.is_some() {
            self.total_errors += 1;
        }

        if let Some(pt) = meta.prompt_tokens {
            self.total_prompt_tokens += pt;
        }
        if let Some(ct) = meta.completion_tokens {
            self.total_completion_tokens += ct;
        }
        if let Some(tt) = meta.total_tokens {
            self.total_tokens += tt;
        }
        if let Some(c) = meta.cost_usd {
            self.total_cost += c;
        }

        if let Some(lt) = meta.latency_ms {
            if lt <= 100 {
                self.latency_buckets[0] += 1;
            } else if lt <= 500 {
                self.latency_buckets[1] += 1;
            } else if lt <= 1000 {
                self.latency_buckets[2] += 1;
            } else if lt <= 5000 {
                self.latency_buckets[3] += 1;
            } else if lt <= 30000 {
                self.latency_buckets[4] += 1;
            } else {
                self.latency_buckets[5] += 1;
            }
        }

        let model = self.per_model.entry(meta.model.clone()).or_default();
        model.requests += 1;
        if meta.error_type.is_some() {
            model.errors += 1;
        }
        if let Some(pt) = meta.prompt_tokens {
            model.prompt_tokens += pt;
        }
        if let Some(ct) = meta.completion_tokens {
            model.completion_tokens += ct;
        }
        if let Some(tt) = meta.total_tokens {
            model.total_tokens += tt;
        }
        if let Some(c) = meta.cost_usd {
            model.cost += c;
        }

        let provider = self
            .per_provider
            .entry(meta.provider.clone())
            .or_insert_with(|| LlmProviderStats {
                requests: 0,
                total_tokens: 0,
                cost: 0.0,
                errors: 0,
            });
        provider.requests += 1;
        if meta.error_type.is_some() {
            provider.errors += 1;
        }
        if let Some(tt) = meta.total_tokens {
            provider.total_tokens += tt;
        }
        if let Some(c) = meta.cost_usd {
            provider.cost += c;
        }

        let family = self
            .per_model_family
            .entry(meta.model_family.clone())
            .or_insert_with(|| LlmModelFamilyStats {
                requests: 0,
                total_tokens: 0,
                cost: 0.0,
            });
        family.requests += 1;
        if let Some(tt) = meta.total_tokens {
            family.total_tokens += tt;
        }
        if let Some(c) = meta.cost_usd {
            family.cost += c;
        }

        *self
            .per_request_type
            .entry(meta.request_type.clone())
            .or_insert(0) += 1;
    }

    pub fn record_session_metrics(&mut self, sm: &LlmSessionMetrics) {
        let model = self.per_model.entry(sm.model.clone()).or_default();
        model.requests += 1;
        model.prompt_tokens += sm.prompt_tokens;
        model.completion_tokens += sm.completion_tokens;
        model.total_tokens += sm.total_tokens;
        model.cost += sm.cost;
        if sm.error_type.is_some() {
            model.errors += 1;
        }

        if sm.ttft_ms > 0 {
            model.ttft_sum_ms += sm.ttft_ms;
            model.ttft_count += 1;
        }

        if sm.stream_duration_ms > 0 && sm.completion_tokens > 0 {
            let tpot_us = (sm.stream_duration_ms * 1000) / sm.completion_tokens;
            model.tpot_sum_us += tpot_us;
            model.tpot_count += 1;
        }

        if sm.stream_duration_ms > 0 {
            let tps = sm.completion_tokens as f64 / (sm.stream_duration_ms as f64 / 1000.0);
            model.tokens_per_second_sum += tps;
            model.tokens_per_second_count += 1;
        }

        match sm.http_status {
            429 => model.rate_limited += 1,
            400..=499 => model.error_4xx += 1,
            500..=599 => model.error_5xx += 1,
            _ => {}
        }

        if sm.streaming {
            model.total_streams += 1;
            if sm.finish_reason != "stop" {
                model.incomplete_streams += 1;
            }
        }

        let provider = self
            .per_provider
            .entry(sm.provider.clone())
            .or_insert_with(|| LlmProviderStats {
                requests: 0,
                total_tokens: 0,
                cost: 0.0,
                errors: 0,
            });
        provider.requests += 1;
        provider.total_tokens += sm.total_tokens;
        provider.cost += sm.cost;
        if sm.error_type.is_some() {
            provider.errors += 1;
        }

        let family = self
            .per_model_family
            .entry(sm.model_family.clone())
            .or_insert_with(|| LlmModelFamilyStats {
                requests: 0,
                total_tokens: 0,
                cost: 0.0,
            });
        family.requests += 1;
        family.total_tokens += sm.total_tokens;
        family.cost += sm.cost;

        *self
            .per_request_type
            .entry(sm.request_type.clone())
            .or_insert(0) += 1;

        let now = Utc::now();

        if sm.ttft_ms > 0 {
            self.latency_heatmap
                .push_back((now, sm.model.clone(), sm.ttft_ms));
            if self.latency_heatmap.len() > self.max_heatmap_points {
                self.latency_heatmap.pop_front();
            }
        }

        self.cost_timeline.push_back((now, sm.cost));
        if self.cost_timeline.len() > 10000 {
            self.cost_timeline.pop_front();
        }
        self.session_cost += sm.cost;
        if (now - self.last_cost_reset).num_days() >= 1 {
            self.daily_cost = sm.cost;
            self.last_cost_reset = now;
        } else {
            self.daily_cost += sm.cost;
        }

        let mut check = |cond: bool, metric: &str, val: String, thr: String| {
            if cond {
                self.anomalies.push_back(AnomalyAlert {
                    model: sm.model.clone(),
                    metric: metric.to_string(),
                    value: val,
                    threshold: thr,
                    timestamp: now,
                });
                if self.anomalies.len() > self.max_anomalies {
                    self.anomalies.pop_front();
                }
            }
        };

        if sm.ttft_ms > 0 {
            check(
                sm.ttft_ms > 500,
                "TTFT",
                format!("{}ms", sm.ttft_ms),
                "500ms".into(),
            );
        }
        if sm.completion_tokens > 0 && sm.stream_duration_ms > 0 {
            let tpot = sm.stream_duration_ms as f64 / sm.completion_tokens as f64;
            check(tpot > 80.0, "TPOT", format!("{:.0}ms", tpot), "80ms".into());
            let tps = sm.completion_tokens as f64 / (sm.stream_duration_ms as f64 / 1000.0);
            check(tps < 20.0, "Tok/s", format!("{:.1}", tps), "20".into());
        }
        if sm.cost > 0.0 {
            check(
                sm.cost > 0.10,
                "Maliyet",
                format!("${:.4}", sm.cost),
                "$0.10".into(),
            );
        }
        match sm.http_status {
            429 => check(true, "Rate Limit", "429".into(), "429".into()),
            400..=499 => check(
                true,
                "4xx Hata",
                format!("{}", sm.http_status),
                "4xx".into(),
            ),
            500..=599 => check(
                true,
                "5xx Hata",
                format!("{}", sm.http_status),
                "5xx".into(),
            ),
            _ => {}
        }
        if sm.streaming && sm.finish_reason != "stop" {
            check(
                true,
                "Stream Kesintisi",
                sm.finish_reason.clone(),
                "stop".into(),
            );
        }
    }

    pub fn peek_anomalies(&self) -> &VecDeque<AnomalyAlert> {
        &self.anomalies
    }

    pub fn drain_anomalies(&mut self) -> Vec<AnomalyAlert> {
        self.anomalies.drain(..).collect()
    }

    pub fn clear_timelines(&mut self) {
        self.latency_heatmap.clear();
        self.cost_timeline.clear();
    }
}

/// Per-flow LLM request/response tracker.
#[derive(Debug, Clone)]
pub struct LlmFlowTracker {
    active: HashMap<(String, u16, String, u16), LlmFlowEntry>,
    completed: Vec<LlmFlowEntry>,
}

#[derive(Debug, Clone)]
pub struct LlmFlowEntry {
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub provider: String,
    pub model: String,
    pub request_type: String,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub finish_reason: Option<String>,
    pub streaming: bool,
    pub error_type: Option<String>,
    pub tool_calls: bool,
    pub cost_usd: Option<f64>,
    pub request_count: u64,
    pub last_seen: u64,
}

impl Default for LlmFlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmFlowTracker {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            completed: Vec::new(),
        }
    }

    pub fn record(
        &mut self,
        meta: &LlmMetadata,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) {
        let key = (src_ip.to_string(), src_port, dst_ip.to_string(), dst_port);
        let entry = self
            .active
            .entry(key.clone())
            .or_insert_with(|| LlmFlowEntry {
                src_addr: src_ip.to_string(),
                src_port,
                dst_addr: dst_ip.to_string(),
                dst_port,
                provider: meta.provider.clone(),
                model: meta.model.clone(),
                request_type: meta.request_type.clone(),
                prompt_tokens: None,
                completion_tokens: None,
                total_tokens: None,
                finish_reason: None,
                streaming: meta.streaming,
                error_type: None,
                tool_calls: false,
                cost_usd: None,
                request_count: 0,
                last_seen: 0,
            });
        entry.request_count += 1;
        entry.provider = meta.provider.clone();
        if !meta.model.is_empty() {
            entry.model = meta.model.clone();
        }
        if meta.prompt_tokens.is_some() {
            entry.prompt_tokens = meta.prompt_tokens;
        }
        if meta.completion_tokens.is_some() {
            entry.completion_tokens = meta.completion_tokens;
        }
        if meta.total_tokens.is_some() {
            entry.total_tokens = meta.total_tokens;
        }
        if meta.finish_reason.is_some() {
            entry.finish_reason = meta.finish_reason.clone();
        }
        if meta.error_type.is_some() {
            entry.error_type = meta.error_type.clone();
        }
        if meta.tool_calls {
            entry.tool_calls = true;
        }
        if meta.cost_usd.is_some() {
            entry.cost_usd = meta.cost_usd;
        }
        if meta.finish_reason.is_some() || meta.total_tokens.is_some() {
            if let Some(e) = self.active.remove(&key) {
                self.completed.push(e);
            }
        }
    }

    pub fn active_flows(&self) -> usize {
        self.active.len()
    }

    pub fn completed_flows(&self) -> &[LlmFlowEntry] {
        &self.completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_field() {
        let raw = r#"{"model":"gpt-4","finish_reason":"stop"}"#;
        assert_eq!(extract_json_field(raw, "model"), Some("gpt-4".into()));
        assert_eq!(
            extract_json_field(raw, "finish_reason"),
            Some("stop".into())
        );
        assert_eq!(extract_json_field(raw, "nonexistent"), None);
    }

    #[test]
    fn test_extract_json_field_escaped() {
        let raw = r#"{"error":"Message \"too long\" rejected"}"#;
        assert_eq!(
            extract_json_field(raw, "error"),
            Some(r#"Message \"too long\" rejected"#.into())
        );
    }

    #[test]
    fn test_extract_json_number() {
        let raw = r#"{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}"#;
        assert_eq!(extract_json_number(raw, "prompt_tokens"), Some(10));
        assert_eq!(extract_json_number(raw, "completion_tokens"), Some(20));
        assert_eq!(extract_json_number(raw, "total_tokens"), Some(30));
        assert_eq!(extract_json_number(raw, "nonexistent"), None);
    }

    #[test]
    fn test_extract_json_number_whitespace() {
        let raw = r#"{"prompt_tokens": 10}"#;
        assert_eq!(extract_json_number(raw, "prompt_tokens"), Some(10));
    }

    #[test]
    fn test_extract_nested_json_field() {
        let raw = r#"{"usage":{"prompt_tokens":5,"completion_tokens":10}}"#;
        assert_eq!(extract_nested_json_number(raw, "prompt_tokens"), Some(5));
        assert_eq!(
            extract_nested_json_number(raw, "completion_tokens"),
            Some(10)
        );
    }

    #[test]
    fn test_extract_llm_metadata_openai() {
        let raw = br#"data: {"choices":[{"delta":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let meta = extract_llm_metadata(raw, &Protocol::OpenaiChatStream).expect("should extract");
        assert_eq!(meta.provider, "openai");
        assert!(meta.streaming);
        assert_eq!(meta.request_type, "chat");
        assert_eq!(meta.prompt_tokens, Some(10));
        assert_eq!(meta.completion_tokens, Some(5));
        assert_eq!(meta.total_tokens, Some(15));
        assert_eq!(meta.finish_reason, Some("stop".into()));
    }

    #[test]
    fn test_extract_llm_metadata_anthropic() {
        let raw = br#"data: {"type":"message_start","message":{"id":"msg1","model":"claude-3-sonnet","usage":{"input_tokens":50,"output_tokens":30}}}"#;
        let meta =
            extract_llm_metadata(raw, &Protocol::AnthropicStreamEvt).expect("should extract");
        assert_eq!(meta.provider, "anthropic");
        assert_eq!(meta.model, "claude-3-sonnet");
        assert_eq!(meta.model_family, "claude-3");
        assert_eq!(meta.prompt_tokens, Some(50));
        assert_eq!(meta.completion_tokens, Some(30));
    }

    #[test]
    fn test_extract_llm_metadata_gemini() {
        let raw = br#"data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10,"totalTokenCount":30}}"#;
        let meta =
            extract_llm_metadata(raw, &Protocol::GoogleGeminiRestStream).expect("should extract");
        assert_eq!(meta.provider, "google");
        assert!(meta.streaming);
    }

    #[test]
    fn test_extract_llm_metadata_non_llm() {
        let raw = b"GET / HTTP/1.1";
        assert!(extract_llm_metadata(raw, &Protocol::Http).is_none());
    }

    #[test]
    fn test_classify_model_family() {
        assert_eq!(classify_model_family("gpt-4-turbo"), "gpt-4");
        assert_eq!(classify_model_family("gpt-3.5-turbo"), "gpt-3.5");
        assert_eq!(classify_model_family("claude-3-opus"), "claude-3");
        assert_eq!(classify_model_family("gemini-1.5-pro"), "gemini-1.5");
        assert_eq!(classify_model_family("llama-3-70b"), "llama-3");
        assert_eq!(classify_model_family("mistral-large"), "mistral-large");
        assert_eq!(classify_model_family("deepseek-chat"), "deepseek");
        assert_eq!(classify_model_family("grok-2"), "grok");
        assert_eq!(classify_model_family("unknown-model"), "");
    }

    #[test]
    fn test_estimate_cost_openai() {
        let cost = estimate_cost("openai", "gpt-4-turbo", Some(1000), Some(500));
        assert!(cost.is_some());
        let c = cost.unwrap();
        assert!(c > 0.0);
    }

    #[test]
    fn test_strip_sse_prefix() {
        assert_eq!(strip_sse_prefix("data: hello"), "hello");
        assert_eq!(
            strip_sse_prefix("data: {\"key\":\"val\"}"),
            "{\"key\":\"val\"}"
        );
        assert_eq!(strip_sse_prefix("plain text"), "plain text");
    }

    #[test]
    fn test_llm_analytics_record() {
        let mut analytics = LlmAnalytics::default();
        let meta = LlmMetadata {
            provider: "openai".into(),
            model: "gpt-4".into(),
            model_family: "gpt-4".into(),
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            total_tokens: Some(30),
            finish_reason: Some("stop".into()),
            request_type: "chat".into(),
            streaming: true,
            error_type: None,
            tool_calls: false,
            cost_usd: Some(0.001),
            latency_ms: Some(200),
        };
        analytics.record(&meta);
        assert_eq!(analytics.total_requests, 1);
        assert_eq!(analytics.total_prompt_tokens, 10);
        assert_eq!(analytics.streaming_requests, 1);
        assert_eq!(analytics.non_streaming_requests, 0);
        assert!(analytics.total_cost > 0.0);
        assert_eq!(analytics.latency_buckets[1], 1);
        assert_eq!(analytics.per_model["gpt-4"].requests, 1);
        assert_eq!(analytics.per_provider["openai"].requests, 1);
        assert_eq!(analytics.per_model_family["gpt-4"].requests, 1);
        assert_eq!(analytics.per_request_type["chat"], 1);
    }

    #[test]
    fn test_llm_analytics_error() {
        let mut analytics = LlmAnalytics::default();
        let meta = LlmMetadata {
            provider: "openai".into(),
            model: "gpt-4".into(),
            model_family: "gpt-4".into(),
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            finish_reason: None,
            request_type: "chat".into(),
            streaming: true,
            error_type: Some("rate_limit_exceeded".into()),
            tool_calls: false,
            cost_usd: None,
            latency_ms: None,
        };
        analytics.record(&meta);
        assert_eq!(analytics.total_errors, 1);
        assert_eq!(analytics.per_model["gpt-4"].errors, 1);
        assert_eq!(analytics.per_provider["openai"].errors, 1);
    }

    #[test]
    fn test_llm_analytics_nested_tokens() {
        let raw = br#"data: {"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":8,"total_tokens":13}}"#;
        let meta = extract_llm_metadata(raw, &Protocol::OpenaiChatStream).expect("should extract");
        assert_eq!(meta.prompt_tokens, Some(5));
        assert_eq!(meta.completion_tokens, Some(8));
        assert_eq!(meta.total_tokens, Some(13));
    }

    #[test]
    fn test_llm_flow_tracker() {
        let mut ft = LlmFlowTracker::new();
        let meta = LlmMetadata {
            provider: "openai".into(),
            model: "gpt-4".into(),
            model_family: "gpt-4".into(),
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            total_tokens: Some(30),
            finish_reason: Some("stop".into()),
            request_type: "chat".into(),
            streaming: true,
            error_type: None,
            tool_calls: false,
            cost_usd: Some(0.001),
            latency_ms: None,
        };
        ft.record(&meta, "10.0.0.1", 50000, "api.openai.com", 443);
        assert_eq!(ft.completed_flows().len(), 1);
        assert_eq!(ft.active_flows(), 0);
        assert_eq!(ft.completed_flows()[0].request_count, 1);
    }

    #[test]
    fn test_provider_openai() {
        assert_eq!(
            provider_from_protocol(&Protocol::OpenaiChatStream),
            "openai"
        );
        assert_eq!(
            provider_from_protocol(&Protocol::OpenaiResponsesApi),
            "openai"
        );
    }

    #[test]
    fn test_provider_anthropic() {
        assert_eq!(
            provider_from_protocol(&Protocol::AnthropicStreamEvt),
            "anthropic"
        );
    }

    #[test]
    fn test_provider_google() {
        assert_eq!(
            provider_from_protocol(&Protocol::GoogleGeminiRestStream),
            "google"
        );
    }

    #[test]
    fn test_request_type_classification() {
        assert_eq!(
            request_type_from_protocol(&Protocol::OpenaiChatStream),
            "chat"
        );
        assert_eq!(
            request_type_from_protocol(&Protocol::OpenaiRealtimeWs),
            "realtime"
        );
        assert_eq!(
            request_type_from_protocol(&Protocol::OpenaiModerationAsync),
            "moderation"
        );
    }

    #[test]
    fn test_extract_error_rate_limit() {
        let raw = r#"{"error":{"code":"rate_limit_exceeded","type":"rate_limit_error"}}"#;
        let err = extract_error(raw, "openai");
        assert!(err.is_some());
    }

    #[test]
    fn test_extract_tool_calls() {
        let raw = r#"{"choices":[{"delta":{"tool_calls":[{"function":{"name":"get_weather"}}]}}]}"#;
        let meta = extract_llm_metadata(raw.as_bytes(), &Protocol::OpenaiChatStream)
            .expect("should extract");
        assert!(meta.tool_calls);
    }

    #[test]
    fn test_estimate_cost_zero_for_free_tier() {
        let cost = estimate_cost("groq", "llama3-70b", Some(1000), Some(500));
        assert_eq!(cost, Some(0.0));
    }

    #[test]
    fn test_estimate_cost_none_for_unknown() {
        let cost = estimate_cost("unknown", "unknown-model", Some(100), Some(50));
        assert_eq!(cost, None);
    }

    #[test]
    fn test_model_family_fallback_to_empty() {
        let meta = LlmMetadata {
            provider: "openai".into(),
            model: String::new(),
            model_family: String::new(),
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            finish_reason: None,
            request_type: "chat".into(),
            streaming: true,
            error_type: None,
            tool_calls: false,
            cost_usd: None,
            latency_ms: None,
        };
        let mut analytics = LlmAnalytics::default();
        analytics.record(&meta);
        assert_eq!(analytics.total_requests, 1);
    }

    #[test]
    fn test_ai_anomaly_alerts_ttft() {
        let mut analytics = LlmAnalytics::default();
        let sm = LlmSessionMetrics {
            model: "gpt-4o".into(),
            provider: "openai".into(),
            model_family: "gpt-4".into(),
            request_type: "chat".into(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            cost: 0.01,
            ttft_ms: 650, // > 500ms
            stream_duration_ms: 1000,
            http_status: 200,
            streaming: true,
            finish_reason: "stop".into(),
            error_type: None,
            prompt_text: String::new(),
            response_text: String::new(),
        };
        analytics.record_session_metrics(&sm);
        let anomalies = analytics.peek_anomalies();
        assert!(anomalies
            .iter()
            .any(|a| a.metric == "TTFT" && a.value == "650ms"));
    }

    #[test]
    fn test_ai_anomaly_alerts_tpot_and_tps() {
        let mut analytics = LlmAnalytics::default();
        let sm = LlmSessionMetrics {
            model: "claude-3-opus".into(),
            provider: "anthropic".into(),
            model_family: "claude-3".into(),
            request_type: "chat".into(),
            prompt_tokens: 100,
            completion_tokens: 10,
            total_tokens: 110,
            cost: 0.01,
            ttft_ms: 100,
            stream_duration_ms: 1000, // 1000ms / 10 tokens = 100ms TPOT (>80ms), 10 tokens / 1s = 10 TPS (<20)
            http_status: 200,
            streaming: true,
            finish_reason: "stop".into(),
            error_type: None,
            prompt_text: String::new(),
            response_text: String::new(),
        };
        analytics.record_session_metrics(&sm);
        let anomalies = analytics.peek_anomalies();
        assert!(anomalies.iter().any(|a| a.metric == "TPOT"));
        assert!(anomalies.iter().any(|a| a.metric == "Tok/s"));
    }

    #[test]
    fn test_ai_anomaly_alerts_bill_shock() {
        let mut analytics = LlmAnalytics::default();
        let sm = LlmSessionMetrics {
            model: "gpt-4".into(),
            provider: "openai".into(),
            model_family: "gpt-4".into(),
            request_type: "chat".into(),
            prompt_tokens: 10000,
            completion_tokens: 2000,
            total_tokens: 12000,
            cost: 0.25, // > $0.10
            ttft_ms: 200,
            stream_duration_ms: 1000,
            http_status: 200,
            streaming: false,
            finish_reason: "stop".into(),
            error_type: None,
            prompt_text: String::new(),
            response_text: String::new(),
        };
        analytics.record_session_metrics(&sm);
        let anomalies = analytics.peek_anomalies();
        assert!(anomalies
            .iter()
            .any(|a| a.metric == "Maliyet" && a.value == "$0.2500"));
    }

    #[test]
    fn test_ai_anomaly_alerts_rate_limit() {
        let mut analytics = LlmAnalytics::default();
        let sm = LlmSessionMetrics {
            model: "gemini-1.5-pro".into(),
            provider: "google".into(),
            model_family: "gemini".into(),
            request_type: "chat".into(),
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            cost: 0.0,
            ttft_ms: 0,
            stream_duration_ms: 0,
            http_status: 429, // Rate limit
            streaming: false,
            finish_reason: "".into(),
            error_type: Some("rate_limit_exceeded".into()),
            prompt_text: String::new(),
            response_text: String::new(),
        };
        analytics.record_session_metrics(&sm);
        let anomalies = analytics.peek_anomalies();
        assert!(anomalies
            .iter()
            .any(|a| a.metric == "Rate Limit" && a.value == "429"));
    }

    #[test]
    fn test_ai_anomaly_alerts_incomplete_stream() {
        let mut analytics = LlmAnalytics::default();
        let sm = LlmSessionMetrics {
            model: "deepseek-coder".into(),
            provider: "deepseek".into(),
            model_family: "deepseek".into(),
            request_type: "chat".into(),
            prompt_tokens: 50,
            completion_tokens: 30,
            total_tokens: 80,
            cost: 0.005,
            ttft_ms: 150,
            stream_duration_ms: 1000,
            http_status: 200,
            streaming: true,
            finish_reason: "length".into(), // != "stop"
            error_type: None,
            prompt_text: String::new(),
            response_text: String::new(),
        };
        analytics.record_session_metrics(&sm);
        let anomalies = analytics.peek_anomalies();
        assert!(anomalies
            .iter()
            .any(|a| a.metric == "Stream Kesintisi" && a.value == "length"));
    }
}
