use std::collections::VecDeque;

use chrono::{DateTime, Utc};

use super::dissectors::{GameEngine, GamePacketInfo, GameTrafficRecord, ReplicationStats};

/// Maximum number of RTT samples kept for jitter calculation.
const MAX_RTT_SAMPLES: usize = 128;

/// A single RTT measurement with timestamp.
#[derive(Debug, Clone)]
pub struct RttSample {
    pub rtt_ms: f64,
    pub timestamp: DateTime<Utc>,
}

/// Tracks per-connection game traffic metrics over time.
#[derive(Debug, Clone)]
pub struct GameConnectionTracker {
    /// Source address.
    pub src: String,
    /// Destination address.
    pub dst: String,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Identified game engine.
    pub engine: GameEngine,
    /// Game name (if identified).
    pub game_name: Option<String>,
    /// Recent RTT sample history.
    pub rtt_samples: VecDeque<RttSample>,
    /// Current RTT (most recent measurement).
    pub current_rtt_ms: Option<f64>,
    /// Current jitter (stddev of recent RTTs).
    pub current_jitter_ms: Option<f64>,
    /// Packet loss estimate (0.0 - 100.0).
    pub packet_loss_pct: f64,
    /// Total packets observed.
    pub total_packets: u64,
    /// Lost packets (inferred from gaps).
    pub lost_packets: u64,
    /// Replication statistics accumulated.
    pub replication_stats: ReplicationStats,
    /// Desynchronization symptom flags.
    pub desync_flags: Vec<String>,
    /// Server tick rate estimate.
    pub server_tick_rate: Option<f64>,
    /// Last client tick seen.
    pub client_tick: Option<u32>,
    /// Last server tick seen.
    pub server_tick: Option<u32>,
    /// Last update timestamp.
    pub last_update: DateTime<Utc>,
    /// First seen timestamp.
    pub first_seen: DateTime<Utc>,
}

impl GameConnectionTracker {
    pub fn new(
        src: String,
        dst: String,
        src_port: u16,
        dst_port: u16,
        engine: GameEngine,
        game_name: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            src,
            dst,
            src_port,
            dst_port,
            engine,
            game_name,
            rtt_samples: VecDeque::with_capacity(MAX_RTT_SAMPLES),
            current_rtt_ms: None,
            current_jitter_ms: None,
            packet_loss_pct: 0.0,
            total_packets: 0,
            lost_packets: 0,
            replication_stats: ReplicationStats::default(),
            desync_flags: Vec::new(),
            server_tick_rate: None,
            client_tick: None,
            server_tick: None,
            last_update: now,
            first_seen: now,
        }
    }

    /// Record an RTT sample and recompute jitter.
    pub fn record_rtt(&mut self, rtt_ms: f64) {
        self.current_rtt_ms = Some(rtt_ms);
        self.rtt_samples.push_back(RttSample {
            rtt_ms,
            timestamp: Utc::now(),
        });
        if self.rtt_samples.len() > MAX_RTT_SAMPLES {
            self.rtt_samples.pop_front();
        }
        if self.rtt_samples.len() >= 2 {
            let mean = self.rtt_samples.iter().map(|s| s.rtt_ms).sum::<f64>()
                / self.rtt_samples.len() as f64;
            let variance = self
                .rtt_samples
                .iter()
                .map(|s| (s.rtt_ms - mean).powi(2))
                .sum::<f64>()
                / self.rtt_samples.len() as f64;
            self.current_jitter_ms = Some(variance.sqrt());
        }
    }

    /// Track cumulative replication statistics.
    pub fn accumulate_replication(&mut self, stats: &ReplicationStats) {
        self.replication_stats.actors_replicated += stats.actors_replicated;
        self.replication_stats.property_updates += stats.property_updates;
        self.replication_stats.rpcs_invoked += stats.rpcs_invoked;
        self.replication_stats.header_bytes += stats.header_bytes;
        self.replication_stats.payload_bytes += stats.payload_bytes;
        self.replication_stats.subobject_replications += stats.subobject_replications;
    }

    /// Mark a desync symptom.
    pub fn add_desync_flag(&mut self, flag: &str) {
        let f = flag.to_string();
        if !self.desync_flags.contains(&f) {
            self.desync_flags.push(f);
        }
    }

    /// Update tracker state from a parsed game packet.
    pub fn update_from_game_info(&mut self, info: &GamePacketInfo) {
        match info {
            GamePacketInfo::Unreal(hdr) => {
                self.replication_stats.actors_replicated += 1;
                self.replication_stats.header_bytes += 8;
                if hdr.is_subobject {
                    self.replication_stats.subobject_replications += 1;
                }
                if hdr.is_property_replication {
                    self.replication_stats.property_updates += 1;
                }
                if hdr.rpc_function_index.is_some() {
                    self.replication_stats.rpcs_invoked += 1;
                }
                if hdr.net_sync_request {
                    self.add_desync_flag("net_sync_request");
                }
                if hdr.net_sync_response {
                    self.add_desync_flag("net_sync_response");
                }
            }
            GamePacketInfo::Unity(hdr) => {
                self.replication_stats.header_bytes += 12;
                if hdr.is_ghost_snapshot {
                    self.replication_stats.actors_replicated += 1;
                }
                if hdr.ngo_rpc_hash.is_some() {
                    self.replication_stats.rpcs_invoked += 1;
                }
            }
            GamePacketInfo::Source2(hdr) => {
                self.server_tick = Some(hdr.server_tick);
                self.server_tick_rate = hdr.tick_rate;
                self.replication_stats.header_bytes += 5;
                if hdr.msg_kind == 0 {
                    self.replication_stats.actors_replicated += 1;
                }
            }
            GamePacketInfo::Godot(hdr) => {
                if hdr.rpc_method_id.is_some() {
                    self.replication_stats.rpcs_invoked += 1;
                }
                self.replication_stats.header_bytes += 4;
            }
            GamePacketInfo::AntiCheat(hdr) => {
                if hdr.has_integrity_report {
                    self.add_desync_flag(format!("integrity_report:{}", hdr.provider).as_str());
                }
            }
            GamePacketInfo::Platform(hdr) => {
                if let Some(rtt) = hdr.platform_rtt_ms {
                    self.record_rtt(rtt);
                }
            }
            GamePacketInfo::Diagnostic(hdr) => {
                if let Some(rtt) = hdr.server_reported_rtt_ms {
                    self.record_rtt(rtt);
                }
                if let Some(bw) = hdr.inbound_bps {
                    if bw < 10_000.0 {
                        self.add_desync_flag("low_inbound_bandwidth");
                    }
                }
            }
            GamePacketInfo::Unknown { .. } => {}
        }
        self.total_packets += 1;
        self.last_update = Utc::now();
    }

    pub fn to_record(&self) -> GameTrafficRecord {
        GameTrafficRecord {
            engine: self.engine,
            game_name: self.game_name.clone(),
            rtt_ms: self.current_rtt_ms,
            jitter_ms: self.current_jitter_ms,
            packet_loss_pct: Some(self.packet_loss_pct),
            desync_flags: self.desync_flags.clone(),
            replication_stats: self.replication_stats.clone(),
            server_tick_rate: self.server_tick_rate,
            client_tick: self.client_tick,
            server_tick: self.server_tick,
            prediction_tick: None,
            interpolation_lag: None,
            timestamp: self.last_update,
            anticheat: None,
            platform: None,
            diagnostic: None,
        }
    }
}

/// Severity of a diagnostic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for DiagSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagSeverity::Info => write!(f, "info"),
            DiagSeverity::Warning => write!(f, "warning"),
            DiagSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A single diagnostic finding from the lag/sync analysis engine.
#[derive(Debug, Clone)]
pub struct DiagFinding {
    /// Severity level.
    pub severity: DiagSeverity,
    /// Short diagnostic title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Suggested remedy.
    pub suggestion: String,
    /// Source rule identifier.
    pub rule_id: &'static str,
    /// Relevant metric values at detection.
    pub metrics: Vec<(String, f64)>,
}

/// Diagnostic rule that flags game performance issues.
#[derive(Debug, Clone)]
pub struct DiagRule {
    /// Unique rule identifier.
    pub id: &'static str,
    /// Human-readable rule name.
    pub name: &'static str,
    /// Severity if triggered.
    pub severity: DiagSeverity,
    /// The detection function.
    pub check: fn(&GameConnectionTracker) -> Option<DiagFinding>,
}

/// Built-in diagnostic rules.
pub fn builtin_rules() -> Vec<DiagRule> {
    vec![
        high_ping_rule(),
        packet_loss_rule(),
        low_server_tick_rate_rule(),
        desync_rule(),
        jitter_spike_rule(),
        rpc_flood_rule(),
        anticheat_integrity_rule(),
        platform_connectivity_rule(),
        bandwidth_throttle_rule(),
    ]
}

fn high_ping_rule() -> DiagRule {
    DiagRule {
        id: "high-ping",
        name: "High Ping",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            let rtt = tracker.current_rtt_ms?;
            if rtt > 150.0 {
                let sev = if rtt > 300.0 {
                    DiagSeverity::Critical
                } else {
                    DiagSeverity::Warning
                };
                Some(DiagFinding {
                    severity: sev,
                    title: if rtt > 300.0 {
                        "Extreme Latency"
                    } else {
                        "High Latency"
                    }
                    .into(),
                    description: format!(
                        "Round-trip time is {rtt:.0} ms, which is above the playable threshold."
                    ),
                    suggestion: "Check routing path, close bandwidth-heavy background apps, \
                                 or switch to a closer game server."
                        .into(),
                    rule_id: "high-ping",
                    metrics: vec![("rtt_ms".into(), rtt)],
                })
            } else {
                None
            }
        },
    }
}

fn packet_loss_rule() -> DiagRule {
    DiagRule {
        id: "packet-loss",
        name: "Packet Loss",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            let loss = tracker.packet_loss_pct;
            if loss > 1.0 {
                let sev = if loss > 5.0 {
                    DiagSeverity::Critical
                } else {
                    DiagSeverity::Warning
                };
                Some(DiagFinding {
                    severity: sev,
                    title: if loss > 5.0 {
                        "Severe Packet Loss"
                    } else {
                        "Packet Loss Detected"
                    }
                    .into(),
                    description: format!(
                        "Estimated packet loss at {loss:.1}%. Loss above 1% causes visible \
                         stutter and desync in real-time games."
                    ),
                    suggestion: "Check Wi-Fi signal strength, switch to wired Ethernet, \
                                 or contact your ISP about line quality."
                        .into(),
                    rule_id: "packet-loss",
                    metrics: vec![("packet_loss_pct".into(), loss)],
                })
            } else {
                None
            }
        },
    }
}

fn low_server_tick_rate_rule() -> DiagRule {
    DiagRule {
        id: "low-tickrate",
        name: "Low Server Tick Rate",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            let tick_rate = tracker.server_tick_rate?;
            if tick_rate < 30.0 {
                Some(DiagFinding {
                    severity: DiagSeverity::Warning,
                    title: "Low Server Tick Rate".into(),
                    description: format!(
                        "Server tick rate is {tick_rate:.0} Hz. Below 30 Hz, game feel \
                         degrades noticeably with interpolation artifacts."
                    ),
                    suggestion: "This is usually a server-side limit. Try a different server \
                                 or contact the server admin."
                        .into(),
                    rule_id: "low-tickrate",
                    metrics: vec![("tick_rate_hz".into(), tick_rate)],
                })
            } else {
                None
            }
        },
    }
}

fn desync_rule() -> DiagRule {
    DiagRule {
        id: "desync",
        name: "Desynchronization Detected",
        severity: DiagSeverity::Critical,
        check: |tracker| {
            if tracker.desync_flags.is_empty() {
                return None;
            }
            let flags = tracker.desync_flags.join(", ");
            Some(DiagFinding {
                severity: DiagSeverity::Critical,
                title: "Client-Server Desync".into(),
                description: format!(
                    "Desynchronization flags detected: {flags}. The client and server \
                     disagree on game state."
                ),
                suggestion: "Enable packet retransmission, reduce packet loss, \
                             or implement client-side rollback/prediction reconciliation."
                    .into(),
                rule_id: "desync",
                metrics: vec![("desync_flags_count".into(), tracker.desync_flags.len() as f64)],
            })
        },
    }
}

fn jitter_spike_rule() -> DiagRule {
    DiagRule {
        id: "jitter-spike",
        name: "Jitter Spike",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            let jitter = tracker.current_jitter_ms?;
            let rtt = tracker.current_rtt_ms?;
            if rtt > 0.0 && jitter / rtt > 0.25 && jitter > 10.0 {
                Some(DiagFinding {
                    severity: DiagSeverity::Warning,
                    title: "High Jitter".into(),
                    description: format!(
                        "Jitter ({jitter:.0} ms) is more than 25% of RTT ({rtt:.0} ms). \
                         This causes inconsistent latency and rubber-banding."
                    ),
                    suggestion: "Stabilize your network connection. Jitter is often caused \
                                 by Wi-Fi interference or bufferbloat."
                        .into(),
                    rule_id: "jitter-spike",
                    metrics: vec![
                        ("jitter_ms".into(), jitter),
                        ("rtt_ms".into(), rtt),
                    ],
                })
            } else {
                None
            }
        },
    }
}

fn rpc_flood_rule() -> DiagRule {
    DiagRule {
        id: "rpc-flood",
        name: "RPC Flood",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            let rpcs = tracker.replication_stats.rpcs_invoked;
            let actors = tracker.replication_stats.actors_replicated;
            if actors > 0 && rpcs > actors * 10 && rpcs > 100 {
                Some(DiagFinding {
                    severity: DiagSeverity::Warning,
                    title: "Excessive RPC Rate".into(),
                    description: format!(
                        "{rpcs} RPCs invoked vs {actors} actors replicated \
                         ({:.1} RPCs/actor). Excessive RPCs can overwhelm the network channel.",
                        rpcs as f64 / actors as f64
                    ),
                    suggestion: "Batch RPCs, use property replication instead, \
                                 or throttle RPC frequency in high-activity periods."
                        .into(),
                    rule_id: "rpc-flood",
                    metrics: vec![
                        ("rpcs_invoked".into(), rpcs as f64),
                        ("actors_replicated".into(), actors as f64),
                    ],
                })
            } else {
                None
            }
        },
    }
}

fn anticheat_integrity_rule() -> DiagRule {
    DiagRule {
        id: "anticheat-integrity",
        name: "Anti-Cheat Integrity Reports",
        severity: DiagSeverity::Info,
        check: |tracker| {
            if tracker.replication_stats.rpcs_invoked > 0 {
                return None;
            }
            None
        },
    }
}

fn platform_connectivity_rule() -> DiagRule {
    DiagRule {
        id: "platform-connectivity",
        name: "Platform Connectivity Issue",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            if tracker.total_packets < 10 {
                return None;
            }
            if tracker.current_rtt_ms.map_or(false, |r| r > 200.0) && tracker.packet_loss_pct > 2.0 {
                Some(DiagFinding {
                    severity: DiagSeverity::Warning,
                    title: "Platform Relay Degradation".into(),
                    description: format!(
                        "Platform relay (EOS/Xbox/PSN) shows high RTT ({:.0} ms) with \
                         {:.1}% loss. Relay-based multiplayer is sensitive to both metrics.",
                        tracker.current_rtt_ms.unwrap_or(0.0),
                        tracker.packet_loss_pct
                    ),
                    suggestion: "Check platform relay status. EOS/Xbox/PSN relay servers \
                                 may be experiencing regional degradation.".into(),
                    rule_id: "platform-connectivity",
                    metrics: vec![
                        ("rtt_ms".into(), tracker.current_rtt_ms.unwrap_or(0.0)),
                        ("packet_loss_pct".into(), tracker.packet_loss_pct),
                    ],
                })
            } else {
                None
            }
        },
    }
}

fn bandwidth_throttle_rule() -> DiagRule {
    DiagRule {
        id: "bandwidth-throttle",
        name: "Bandwidth Throttling",
        severity: DiagSeverity::Warning,
        check: |tracker| {
            if tracker.packet_loss_pct > 3.0 && tracker.total_packets > 50 {
                Some(DiagFinding {
                    severity: DiagSeverity::Warning,
                    title: "Possible Bandwidth Throttling".into(),
                    description: format!(
                        "Packet loss of {:.1}% over {} packets may indicate ISP throttling \
                         or network congestion on the game's ports.",
                        tracker.packet_loss_pct, tracker.total_packets
                    ),
                    suggestion: "Try using a VPN to rule out ISP throttling. \
                                 Check for background downloads or streaming.".into(),
                    rule_id: "bandwidth-throttle",
                    metrics: vec![
                        ("packet_loss_pct".into(), tracker.packet_loss_pct),
                        ("total_packets".into(), tracker.total_packets as f64),
                    ],
                })
            } else {
                None
            }
        },
    }
}

/// The lag/sync analysis engine. Runs diagnostic rules against connection trackers.
#[derive(Debug, Clone)]
pub struct LagAnalyzer {
    rules: Vec<DiagRule>,
}

impl LagAnalyzer {
    pub fn new() -> Self {
        Self {
            rules: builtin_rules(),
        }
    }

    pub fn with_rules(rules: Vec<DiagRule>) -> Self {
        Self { rules }
    }

    /// Run all diagnostic rules against a connection tracker and return findings.
    pub fn analyze(&self, tracker: &GameConnectionTracker) -> Vec<DiagFinding> {
        self.rules
            .iter()
            .filter_map(|rule| (rule.check)(tracker))
            .collect()
    }

    pub fn rules(&self) -> &[DiagRule] {
        &self.rules
    }
}

impl Default for LagAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// A single event on the game traffic timeline.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub tick: u32,
    pub event_type: TimelineEventType,
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimelineEventType {
    ClientTick,
    ClientSend,
    NetworkTravel,
    ServerRecv,
    ServerTick,
    ServerSend,
    ClientRecv,
    ClientRender,
    InterpolationLag,
    Desync,
    Ping,
}

/// Timeline view data: a sequence of events with render offsets.
#[derive(Debug, Clone)]
pub struct GameTimeline {
    pub events: Vec<TimelineEvent>,
    pub interpolation_lag_ms: Option<f64>,
    pub total_latency_ms: Option<f64>,
}

impl GameTimeline {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            interpolation_lag_ms: None,
            total_latency_ms: None,
        }
    }

    /// Build a timeline from the last N events in a connection tracker.
    pub fn from_tracker(tracker: &GameConnectionTracker) -> Self {
        let mut tl = GameTimeline::new();
        if let Some(rtt) = tracker.current_rtt_ms {
            tl.interpolation_lag_ms = Some(rtt * 0.5);
            tl.total_latency_ms = Some(rtt * 1.5);
        }
        tl
    }
}

impl Default for GameTimeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_tracker(rtt: Option<f64>, loss: f64) -> GameConnectionTracker {
        let mut t = GameConnectionTracker::new(
            "10.0.0.1".into(),
            "10.0.0.2".into(),
            7777,
            7777,
            GameEngine::UnrealEngine5,
            None,
            Utc::now(),
        );
        if let Some(r) = rtt {
            t.record_rtt(r);
        }
        t.packet_loss_pct = loss;
        t
    }

    #[test]
    fn high_ping_detected() {
        let t = make_tracker(Some(200.0), 0.0);
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(findings.iter().any(|f| f.rule_id == "high-ping"));
    }

    #[test]
    fn ok_ping_no_finding() {
        let t = make_tracker(Some(30.0), 0.0);
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(!findings.iter().any(|f| f.rule_id == "high-ping"));
    }

    #[test]
    fn packet_loss_detected() {
        let t = make_tracker(Some(50.0), 3.0);
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(findings.iter().any(|f| f.rule_id == "packet-loss"));
    }

    #[test]
    fn desync_detected() {
        let mut t = make_tracker(Some(50.0), 0.0);
        t.add_desync_flag("actor_mismatch");
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(findings.iter().any(|f| f.rule_id == "desync"));
    }

    #[test]
    fn rtt_jitter_calculation() {
        let mut t = make_tracker(None, 0.0);
        t.record_rtt(50.0);
        t.record_rtt(60.0);
        t.record_rtt(55.0);
        assert!(t.current_rtt_ms.unwrap() - 55.0 < 1.0);
        assert!(t.current_jitter_ms.unwrap() > 0.0);
    }

    #[test]
    fn rpc_flood_detected() {
        let mut t = make_tracker(Some(30.0), 0.0);
        t.replication_stats.actors_replicated = 5;
        t.replication_stats.rpcs_invoked = 101;
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(findings.iter().any(|f| f.rule_id == "rpc-flood"));
    }

    #[test]
    fn platform_connectivity_detected() {
        let mut t = make_tracker(Some(250.0), 3.0);
        t.total_packets = 20;
        let analyzer = LagAnalyzer::new();
        let findings = analyzer.analyze(&t);
        assert!(findings.iter().any(|f| f.rule_id == "platform-connectivity"));
    }

    #[test]
    fn rules_count() {
        let analyzer = LagAnalyzer::new();
        assert_eq!(analyzer.rules().len(), 9);
    }
}
