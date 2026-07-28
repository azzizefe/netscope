use std::fmt;

use chrono::{DateTime, Utc};

/// Supported game engine families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GameEngine {
    UnrealEngine4,
    UnrealEngine5,
    Unity,
    Source2,
    Godot,
    AntiCheat,
    Platform,
    Diagnostic,
    Custom(&'static str),
}

impl fmt::Display for GameEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GameEngine::UnrealEngine4 => write!(f, "Unreal Engine 4"),
            GameEngine::UnrealEngine5 => write!(f, "Unreal Engine 5"),
            GameEngine::Unity => write!(f, "Unity"),
            GameEngine::Source2 => write!(f, "Source 2"),
            GameEngine::Godot => write!(f, "Godot"),
            GameEngine::AntiCheat => write!(f, "Anti-Cheat"),
            GameEngine::Platform => write!(f, "Game Platform"),
            GameEngine::Diagnostic => write!(f, "Diagnostic"),
            GameEngine::Custom(name) => write!(f, "{name}"),
        }
    }
}

/// Unreal Engine 4/5 packet header (Iris/ReplicationGraph/RPC framing).
#[derive(Debug, Clone, PartialEq)]
pub struct UnrealPacketHeader {
    pub channel_index: u8,
    pub bunch_seq: u32,
    pub is_partial: bool,
    pub rep_graph_node: Option<u32>,
    pub dormancy_level: u8,
    pub net_sync_request: bool,
    pub net_sync_response: bool,
    pub cull_distance: Option<f32>,
    pub is_subobject: bool,
    pub priority: Option<f32>,
    pub is_relevant: bool,
    /// RPC function index (if this is an RPC call).
    pub rpc_function_index: Option<u16>,
    /// Whether this is a property replication (vs RPC or handshake).
    pub is_property_replication: bool,
}

/// Unity Transport Protocol (UTP) packet header + Netcode/Entities metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct UnityTransportPacket {
    pub pipeline_stage: u8,
    pub sequence: u32,
    pub ngo_rpc_hash: Option<u32>,
    pub is_ghost_snapshot: bool,
    pub ghost_id: Option<u32>,
    pub prediction_tick: Option<u32>,
    pub is_state_sync: bool,
    pub input_ack_tick: Option<u32>,
    pub resimulation_tick: Option<u32>,
    /// Entity/NetworkId for DOTS Entities or NGO.
    pub entity_id: Option<u32>,
    /// Whether this is a networked object spawn.
    pub is_spawn: bool,
    /// Whether this is a networked object despawn.
    pub is_despawn: bool,
}

/// Source 2 NetMessage/SVC/UserMessage header.
#[derive(Debug, Clone, PartialEq)]
pub struct Source2PacketHeader {
    /// NetMessage ID (from engine's registered message list).
    pub msg_id: u8,
    /// Server tick at which this message was sent.
    pub server_tick: u32,
    /// SVC message type (0 = SVC_Messages, 1 = UserMessages, 2 = NetMessages).
    pub msg_kind: u8,
    /// Whether this is a reliable message.
    pub is_reliable: bool,
    /// Whether this is a split (fragmented) message requiring reassembly.
    pub is_split: bool,
    /// UserMessage ID (if msg_kind == 1).
    pub user_message_id: Option<u8>,
    /// Estimated tick rate based on inter-tick deltas.
    pub tick_rate: Option<f64>,
}

/// Godot ENet/WebSocket/RPC header.
#[derive(Debug, Clone, PartialEq)]
pub struct GodotPacketHeader {
    /// Underlying transport: 0 = ENet, 1 = WebSocket, 2 = RPC MP.
    pub transport_type: u8,
    /// ENet channel (0-15) or WebSocket stream ID.
    pub channel: u8,
    /// Sequence number for ordering/reliability.
    pub sequence: u16,
    /// Whether the packet is sent reliably.
    pub is_reliable: bool,
    /// RPC method ID (if this is a Godot RPC call).
    pub rpc_method_id: Option<u16>,
    /// Peer ID (used in WebSocket/MP mode).
    pub peer_id: Option<u16>,
    /// Whether this is a network profiler sample.
    pub is_profiler_sample: bool,
}

/// Anti-cheat protocol metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct AntiCheatPacket {
    /// Which anti-cheat system: "vanguard", "battleye", "eac", "denuvo"
    pub provider: String,
    /// Message type (challenge, response, heartbeat, kick, report, etc.).
    pub msg_type: String,
    /// Sequence number for ordered delivery.
    pub sequence: u32,
    /// Whether this is a handshake/auth packet (vs periodic heartbeat).
    pub is_handshake: bool,
    /// Whether this carries a game integrity report.
    pub has_integrity_report: bool,
    /// Whether this is a challenge packet.
    pub is_challenge: bool,
}

/// Platform-level game networking protocol metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct PlatformPacket {
    /// Platform identifier: "steam_sdr", "eos_p2p", "xbox_sdv2", "psn_rtc"
    pub platform: String,
    /// Connection channel or stream ID.
    pub channel: u8,
    /// Sequence for ordered/reliable delivery.
    pub sequence: u32,
    /// Whether the platform provides reliable delivery.
    pub is_reliable: bool,
    /// Number of pending acknowledgements.
    pub ack_count: u8,
    /// Whether this is a connection handshake.
    pub is_handshake: bool,
    /// Peer session ID (if applicable).
    pub session_id: Option<u32>,
    /// Round-trip measurement from platform-level ping/pong (ms).
    pub platform_rtt_ms: Option<f64>,
}

/// Diagnostic/lag metadata extracted from game traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct DiagnosticMetadata {
    /// Source of the diagnostic info: "net_sync", "platform_ping", "tick_jitter"
    pub source: String,
    /// Client-side interpolation buffer depth (bytes).
    pub interp_buffer_bytes: Option<u32>,
    /// Client-side interpolation buffer depth (ms).
    pub interp_buffer_ms: Option<f64>,
    /// Number of replication packets buffered for processing.
    pub rep_queue_depth: Option<u32>,
    /// Server-reported client latency (ms).
    pub server_reported_rtt_ms: Option<f64>,
    /// Whether the server requested a bandwidth cap.
    pub bandwidth_cap_requested: bool,
    /// Inbound bandwidth estimate (bytes/sec).
    pub inbound_bps: Option<f64>,
    /// Outbound bandwidth estimate (bytes/sec).
    pub outbound_bps: Option<f64>,
}

/// Statistics for replication traffic within a connection.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReplicationStats {
    pub actors_replicated: u64,
    pub property_updates: u64,
    pub rpcs_invoked: u64,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub subobject_replications: u64,
}

/// Aggregated game traffic analytics for a single connection/session.
#[derive(Debug, Clone, PartialEq)]
pub struct GameTrafficRecord {
    pub engine: GameEngine,
    pub game_name: Option<String>,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub packet_loss_pct: Option<f64>,
    pub desync_flags: Vec<String>,
    pub replication_stats: ReplicationStats,
    pub server_tick_rate: Option<f64>,
    pub client_tick: Option<u32>,
    pub server_tick: Option<u32>,
    pub prediction_tick: Option<u32>,
    pub interpolation_lag: Option<f64>,
    pub timestamp: DateTime<Utc>,
    /// Anti-cheat specific metadata.
    pub anticheat: Option<AntiCheatPacket>,
    /// Platform-specific metadata.
    pub platform: Option<PlatformPacket>,
    /// Diagnostic metadata.
    pub diagnostic: Option<DiagnosticMetadata>,
}

/// Per-packet dissected game header.
#[derive(Debug, Clone)]
pub enum GamePacketInfo {
    Unreal(UnrealPacketHeader),
    Unity(UnityTransportPacket),
    Source2(Source2PacketHeader),
    Godot(GodotPacketHeader),
    AntiCheat(AntiCheatPacket),
    Platform(PlatformPacket),
    Diagnostic(DiagnosticMetadata),
    Unknown { engine: GameEngine },
}

/// Trait that a game engine dissector plugin must implement.
pub trait GamePluginDissector: Send + Sync {
    fn name(&self) -> &str;
    fn engine(&self) -> GameEngine;
    fn claimed_ports(&self) -> Vec<u16>;
    fn dissect(&self, payload: &[u8], src_port: u16, dst_port: u16) -> Option<GamePacketInfo>;
    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String;
}
