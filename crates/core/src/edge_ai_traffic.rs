use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use chrono::{DateTime, Utc};
use crate::models::Protocol;

static NEXT_EDGE_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub type EdgeSessionId = u64;

fn next_edge_session_id() -> EdgeSessionId {
    NEXT_EDGE_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeAiPlatform {
    OnnxRuntime,
    TensorflowLite,
    PytorchMobile,
    NxpEiq,
    Stm32CubeAi,
    SiemensIndustrialEdge,
    BoschNexeed,
    BeckhoffTwincat,
    RockwellFactorytalk,
    SchneiderEcostruxure,
    Other(String),
}

impl std::fmt::Display for EdgeAiPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeAiPlatform::OnnxRuntime => write!(f, "ONNX Runtime"),
            EdgeAiPlatform::TensorflowLite => write!(f, "TensorFlow Lite"),
            EdgeAiPlatform::PytorchMobile => write!(f, "PyTorch Mobile"),
            EdgeAiPlatform::NxpEiq => write!(f, "NXP eIQ"),
            EdgeAiPlatform::Stm32CubeAi => write!(f, "STM32Cube.AI"),
            EdgeAiPlatform::SiemensIndustrialEdge => write!(f, "Siemens Industrial Edge"),
            EdgeAiPlatform::BoschNexeed => write!(f, "Bosch Nexeed"),
            EdgeAiPlatform::BeckhoffTwincat => write!(f, "Beckhoff TwinCAT"),
            EdgeAiPlatform::RockwellFactorytalk => write!(f, "Rockwell FactoryTalk"),
            EdgeAiPlatform::SchneiderEcostruxure => write!(f, "Schneider EcoStruxure"),
            EdgeAiPlatform::Other(s) => write!(f, "{s}"),
        }
    }
}

impl EdgeAiPlatform {
    pub fn from_protocol(p: &Protocol) -> Option<EdgeAiPlatform> {
        match p {
            Protocol::EdgeInferenceOnnx => Some(EdgeAiPlatform::OnnxRuntime),
            Protocol::EdgeTensorflowLite => Some(EdgeAiPlatform::TensorflowLite),
            Protocol::EdgePytorchMobile => Some(EdgeAiPlatform::PytorchMobile),
            Protocol::NxpEiqInference => Some(EdgeAiPlatform::NxpEiq),
            Protocol::StmStm32cubeAi => Some(EdgeAiPlatform::Stm32CubeAi),
            Protocol::SiemensIndustrialEdge => Some(EdgeAiPlatform::SiemensIndustrialEdge),
            Protocol::BoschNexeedEdge => Some(EdgeAiPlatform::BoschNexeed),
            Protocol::BeckhoffTwincatAnalytics => Some(EdgeAiPlatform::BeckhoffTwincat),
            Protocol::RockwellFactorytalkEdge => Some(EdgeAiPlatform::RockwellFactorytalk),
            Protocol::SchneiderEcostruxureEdge => Some(EdgeAiPlatform::SchneiderEcostruxure),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EdgeAiRecord {
    pub session_id: EdgeSessionId,
    pub platform: EdgeAiPlatform,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub inference_count: u64,
    pub total_bytes: u64,
    pub avg_latency_ms: f64,
    pub status: EdgeInferenceStatus,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub enum EdgeInferenceStatus {
    Success,
    Error,
    Timeout,
    InProgress,
}

#[derive(Debug, Clone)]
pub struct EdgePlatformStats {
    pub sessions: u64,
    pub total_inferences: u64,
    pub total_bytes: u64,
    pub avg_latency_ms: f64,
    pub error_count: u64,
}

#[derive(Debug, Clone, Default)]
pub struct EdgeAiAnalytics {
    pub per_platform: HashMap<EdgeAiPlatform, EdgePlatformStats>,
    pub total_sessions: u64,
    pub total_inferences: u64,
    pub total_bytes: u64,
    pub active_sessions: usize,
    pub per_platform_records: Vec<(EdgeAiPlatform, u64, u64, f64, u64)>,
}

#[derive(Debug)]
pub struct EdgeAiTracker {
    sessions: HashMap<EdgeSessionId, EdgeAiRecord>,
    per_platform: HashMap<EdgeAiPlatform, EdgePlatformStats>,
    total_sessions: u64,
    total_inferences: u64,
    total_bytes: u64,
    active: usize,
}

impl Default for EdgeAiTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeAiTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            per_platform: HashMap::new(),
            total_sessions: 0,
            total_inferences: 0,
            total_bytes: 0,
            active: 0,
        }
    }

    pub fn record_inference(
        &mut self,
        platform: EdgeAiPlatform,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        latency_ms: f64,
        bytes: u64,
        success: bool,
    ) {
        self.total_inferences += 1;
        self.total_bytes += bytes;

        let stats = self.per_platform.entry(platform.clone()).or_insert(EdgePlatformStats {
            sessions: 0,
            total_inferences: 0,
            total_bytes: 0,
            avg_latency_ms: 0.0,
            error_count: 0,
        });
        stats.total_inferences += 1;
        stats.total_bytes += bytes;
        if !success {
            stats.error_count += 1;
        }
        let n = stats.total_inferences as f64;
        stats.avg_latency_ms = stats.avg_latency_ms * ((n - 1.0) / n) + latency_ms / n;
    }

    pub fn snapshot(&self) -> EdgeAiAnalytics {
        let mut per_platform_records: Vec<_> = self.per_platform.iter()
            .map(|(p, s)| (p.clone(), s.total_inferences, s.total_bytes, s.avg_latency_ms, s.error_count))
            .collect();
        per_platform_records.sort_by_key(|(_, inf, _, _, _)| std::cmp::Reverse(*inf));

        EdgeAiAnalytics {
            per_platform: self.per_platform.clone(),
            total_sessions: self.total_sessions,
            total_inferences: self.total_inferences,
            total_bytes: self.total_bytes,
            active_sessions: self.active,
            per_platform_records,
        }
    }
}
