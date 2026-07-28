pub mod analytics;
pub mod dissectors;
pub mod manifest;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;

pub use analytics::{DiagFinding, DiagRule, DiagSeverity, GameConnectionTracker, LagAnalyzer};
pub use dissectors::{
    AntiCheatPacket, DiagnosticMetadata, GameEngine, GamePacketInfo, GamePluginDissector,
    GameTrafficRecord, GodotPacketHeader, PlatformPacket, ReplicationStats, Source2PacketHeader,
    UnityTransportPacket, UnrealPacketHeader,
};
pub use manifest::{GamePluginManifest, PluginMeta, ProtocolDecl};

/// Manages loading, registration, and lifecycle of game engine dissector plugins.
pub struct GamePluginManager {
    /// Registered plugin dissectors keyed by name.
    dissectors: HashMap<String, Box<dyn GamePluginDissector>>,
    /// Known plugin manifests (loaded from `.plugin.toml` files).
    manifests: HashMap<String, GamePluginManifest>,
    /// Active connection trackers keyed by `src:dst:port` tuple.
    connections: HashMap<String, GameConnectionTracker>,
    /// The lag/sync analysis engine.
    analyzer: LagAnalyzer,
    /// Plugin search paths.
    search_paths: Vec<PathBuf>,
}

impl GamePluginManager {
    pub fn new() -> Self {
        Self {
            dissectors: HashMap::new(),
            manifests: HashMap::new(),
            connections: HashMap::new(),
            analyzer: LagAnalyzer::new(),
            search_paths: Vec::new(),
        }
    }

    /// Add a search path for game plugin manifests and dissector modules.
    pub fn add_search_path(&mut self, path: impl Into<PathBuf>) {
        self.search_paths.push(path.into());
    }

    /// Register a plugin dissector implementation.
    pub fn register(&mut self, dissector: Box<dyn GamePluginDissector>) {
        self.dissectors
            .insert(dissector.name().to_string(), dissector);
    }

    /// Load a plugin.toml manifest from disk.
    pub fn load_manifest(&mut self, path: &Path) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let manifest = GamePluginManifest::parse(&text)?;
        manifest.validate().map_err(|errs| errs.join("; "))?;
        let name = manifest.plugin.name.clone();
        self.manifests.insert(name, manifest);
        Ok(())
    }

    /// Load all manifests from the configured search paths.
    pub fn load_all_manifests(&mut self) -> (usize, Vec<String>) {
        let mut loaded = 0;
        let mut errors = Vec::new();
        let paths: Vec<PathBuf> = self.search_paths.clone();
        for path in &paths {
            if !path.exists() {
                continue;
            }
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().is_some_and(|e| e == "toml") && p.file_stem().is_some() {
                            if let Err(e) = self.load_manifest(&p) {
                                errors.push(format!("{}: {e}", p.display()));
                            } else {
                                loaded += 1;
                            }
                        }
                    }
                }
            } else if path.extension().is_some_and(|e| e == "toml") {
                match self.load_manifest(path) {
                    Err(e) => errors.push(format!("{}: {e}", path.display())),
                    Ok(_) => loaded += 1,
                }
            }
        }
        (loaded, errors)
    }

    /// Find a matching plugin dissector for a given payload and ports.
    /// The first dissector whose claimed ports match and whose `dissect()` succeeds wins.
    pub fn find_dissector(
        &self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
    ) -> Option<&dyn GamePluginDissector> {
        for d in self.dissectors.values() {
            let ports = d.claimed_ports();
            if (ports.contains(&src_port) || ports.contains(&dst_port))
                && d.dissect(payload, src_port, dst_port).is_some()
            {
                return Some(d.as_ref());
            }
        }
        None
    }

    /// Get or create a connection tracker for a 5-tuple.
    pub fn get_or_create_tracker(
        &mut self,
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
        engine: GameEngine,
    ) -> &mut GameConnectionTracker {
        let key = connection_key(src, dst, src_port, dst_port);
        let now = Utc::now();
        self.connections.entry(key).or_insert_with(|| {
            GameConnectionTracker::new(
                src.to_string(),
                dst.to_string(),
                src_port,
                dst_port,
                engine,
                None,
                now,
            )
        })
    }

    /// Dissect a single packet through the game plugin system.
    /// Returns `Some(GamePacketInfo)` if a plugin matches, `None` otherwise.
    pub fn dissect_packet(
        &mut self,
        payload: &[u8],
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Option<GamePacketInfo> {
        let dissector = self.find_dissector(payload, src_port, dst_port)?;
        let info = dissector.dissect(payload, src_port, dst_port)?;
        let tracker = self.get_or_create_tracker(src, dst, src_port, dst_port, dissector.engine());
        tracker.update_from_game_info(&info);
        Some(info)
    }

    /// Run diagnostics on all active connections.
    pub fn diagnose_all(&self) -> HashMap<String, Vec<DiagFinding>> {
        let mut results = HashMap::new();
        for (key, tracker) in &self.connections {
            let findings = self.analyzer.analyze(tracker);
            if !findings.is_empty() {
                results.insert(key.clone(), findings);
            }
        }
        results
    }

    /// Run diagnostics on a specific connection.
    pub fn diagnose(&self, src: &str, dst: &str, src_port: u16, dst_port: u16) -> Vec<DiagFinding> {
        let key = connection_key(src, dst, src_port, dst_port);
        self.connections
            .get(&key)
            .map(|t| self.analyzer.analyze(t))
            .unwrap_or_default()
    }

    /// List all active connections with their current game traffic records.
    pub fn active_connections(&self) -> Vec<GameTrafficRecord> {
        self.connections.values().map(|t| t.to_record()).collect()
    }

    pub fn dissectors(&self) -> impl Iterator<Item = &dyn GamePluginDissector> {
        self.dissectors.values().map(|b| b.as_ref())
    }

    pub fn manifests(&self) -> &HashMap<String, GamePluginManifest> {
        &self.manifests
    }

    pub fn analyzer(&self) -> &LagAnalyzer {
        &self.analyzer
    }
}

impl Default for GamePluginManager {
    fn default() -> Self {
        Self::new()
    }
}

fn connection_key(src: &str, dst: &str, src_port: u16, dst_port: u16) -> String {
    format!("{src}:{src_port}->{dst}:{dst_port}")
}

pub struct UnrealIrisDissector;

impl GamePluginDissector for UnrealIrisDissector {
    fn name(&self) -> &str {
        "unreal-engine"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::UnrealEngine5
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![7777, 27015, 7778, 27016]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 8 {
            return None;
        }
        let channel = payload[0];
        let flags = payload[1];
        if channel > 16 {
            return None;
        }
        let bunch_seq = u32::from_le_bytes([
            payload[2],
            payload[3],
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
        ]);
        let rep_graph_node = if payload.len() >= 12 {
            Some(u32::from_le_bytes([
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]))
        } else {
            None
        };
        let rpc_idx = if payload.len() >= 14 {
            Some(u16::from_le_bytes([payload[12], payload[13]]))
        } else {
            None
        };
        Some(GamePacketInfo::Unreal(UnrealPacketHeader {
            channel_index: channel,
            bunch_seq,
            is_partial: (flags & 0x80) != 0,
            rep_graph_node,
            dormancy_level: (flags & 0x0F),
            net_sync_request: (flags & 0x40) != 0,
            net_sync_response: (flags & 0x20) != 0,
            cull_distance: None,
            is_subobject: (flags & 0x01) != 0,
            priority: None,
            is_relevant: true,
            rpc_function_index: rpc_idx,
            is_property_replication: rpc_idx.is_none() && (flags & 0x02) != 0,
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Unreal(hdr) => {
                let mut s = format!("UE Iris ch={} seq={}", hdr.channel_index, hdr.bunch_seq);
                if hdr.is_partial {
                    s.push_str(" PARTIAL");
                }
                if let Some(n) = hdr.rep_graph_node {
                    s.push_str(&format!(" rgn={n}"));
                }
                if let Some(r) = hdr.rpc_function_index {
                    s.push_str(&format!(" RPC#{r}"));
                }
                if hdr.is_property_replication {
                    s.push_str(" prop_rep");
                }
                s.push_str(&format!(" ({} B)", length));
                s
            }
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct UnityTransportDissector;

impl GamePluginDissector for UnityTransportDissector {
    fn name(&self) -> &str {
        "unity-transport"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::Unity
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![14000, 14001, 3074, 3075, 9000]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 12 {
            return None;
        }
        let pipeline = payload[0];
        if pipeline > 5 {
            return None;
        }
        let sequence = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let is_ghost = (payload[1] & 0x01) != 0;
        let ghost_id = if is_ghost {
            Some(u32::from_le_bytes([
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]))
        } else {
            None
        };
        let ngo_hash = if payload.len() >= 16 {
            Some(u32::from_le_bytes([
                payload[12],
                payload[13],
                payload[14],
                payload[15],
            ]))
        } else {
            None
        };
        let entity = if payload.len() >= 20 {
            Some(u32::from_le_bytes([
                payload[16],
                payload[17],
                payload[18],
                payload[19],
            ]))
        } else {
            None
        };
        let prediction = if payload.len() >= 24 {
            Some(u32::from_le_bytes([
                payload[20],
                payload[21],
                payload[22],
                payload[23],
            ]))
        } else {
            None
        };
        Some(GamePacketInfo::Unity(UnityTransportPacket {
            pipeline_stage: pipeline,
            sequence,
            ngo_rpc_hash: ngo_hash,
            is_ghost_snapshot: is_ghost,
            ghost_id,
            prediction_tick: prediction,
            is_state_sync: (payload[1] & 0x02) != 0,
            input_ack_tick: None,
            resimulation_tick: None,
            entity_id: entity,
            is_spawn: (payload[1] & 0x04) != 0,
            is_despawn: (payload[1] & 0x08) != 0,
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Unity(hdr) => {
                let mut s = format!("Unity UTP pipe={} seq={}", hdr.pipeline_stage, hdr.sequence);
                if hdr.is_ghost_snapshot {
                    s.push_str(&format!(" ghost={}", hdr.ghost_id.unwrap_or(0)));
                }
                if let Some(e) = hdr.entity_id {
                    s.push_str(&format!(" entity={e}"));
                }
                s.push_str(&format!(" ({} B)", length));
                s
            }
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct Source2NetmessageDissector;

impl GamePluginDissector for Source2NetmessageDissector {
    fn name(&self) -> &str {
        "source2-netmessage"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::Source2
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![27015, 27016, 26900]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 5 {
            return None;
        }
        let msg_id = payload[0];
        let server_tick = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
        let size = payload[4];
        if size as usize > payload.len() {
            return None;
        }
        Some(GamePacketInfo::Source2(Source2PacketHeader {
            msg_id,
            server_tick,
            msg_kind: if msg_id < 32 {
                0
            } else if msg_id < 64 {
                2
            } else {
                1
            },
            is_reliable: (payload.get(5).copied().unwrap_or(0) & 0x80) != 0,
            is_split: (payload.get(5).copied().unwrap_or(0) & 0x40) != 0,
            user_message_id: if msg_id >= 64 {
                Some(msg_id - 64)
            } else {
                None
            },
            tick_rate: None,
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Source2(hdr) => format!(
                "Source2 NetMsg id={} tick={} kind={} ({} B)",
                hdr.msg_id, hdr.server_tick, hdr.msg_kind, length
            ),
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct GodotEnetDissector;

impl GamePluginDissector for GodotEnetDissector {
    fn name(&self) -> &str {
        "godot-enet"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::Godot
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![9876, 9877, 14000, 14001]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 4 {
            return None;
        }
        let flags = payload[0];
        let channel = payload[1];
        if channel > 15 {
            return None;
        }
        let sequence = u16::from_be_bytes([payload[2], payload[3]]);
        let is_reliable = (flags & 0x80) != 0;
        let rpc_mid = if payload.len() >= 6 {
            Some(u16::from_be_bytes([payload[4], payload[5]]))
        } else {
            None
        };
        let peer_id = if payload.len() >= 8 {
            Some(u16::from_be_bytes([payload[6], payload[7]]))
        } else {
            None
        };
        Some(GamePacketInfo::Godot(GodotPacketHeader {
            transport_type: 0,
            channel,
            sequence,
            is_reliable,
            rpc_method_id: rpc_mid,
            peer_id,
            is_profiler_sample: (flags & 0x01) != 0,
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Godot(hdr) => {
                let rel = if hdr.is_reliable { "R" } else { "U" };
                let mut s = format!("Godot ENet {rel} ch={} seq={}", hdr.channel, hdr.sequence);
                if let Some(r) = hdr.rpc_method_id {
                    s.push_str(&format!(" RPC#{r}"));
                }
                s.push_str(&format!(" ({} B)", length));
                s
            }
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct AntiCheatDissector;

impl GamePluginDissector for AntiCheatDissector {
    fn name(&self) -> &str {
        "anticheat"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::AntiCheat
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![4444, 5555, 6666, 7777, 8888]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 6 {
            return None;
        }
        let proto = payload[0];
        let msg_type = payload[1];
        let seq = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let (provider, msg_name) = match proto {
            0xBE => (
                "battleye",
                if msg_type == 0x00 {
                    "challenge"
                } else if msg_type == 0x01 {
                    "response"
                } else if msg_type == 0x02 {
                    "heartbeat"
                } else if msg_type == 0x03 {
                    "kick"
                } else {
                    "unknown"
                },
            ),
            0xE5 => (
                "eac",
                if msg_type < 0x10 {
                    "handshake"
                } else {
                    "integrity_report"
                },
            ),
            0xDA => ("denuvo", if msg_type < 0x08 { "auth" } else { "heartbeat" }),
            0xEA => (
                "vanguard",
                if msg_type == 0x01 {
                    "challenge"
                } else if msg_type == 0x02 {
                    "response"
                } else {
                    "heartbeat"
                },
            ),
            _ => return None,
        };
        Some(GamePacketInfo::AntiCheat(AntiCheatPacket {
            provider: provider.into(),
            msg_type: msg_name.into(),
            sequence: seq,
            is_handshake: matches!(msg_name, "challenge" | "response" | "auth"),
            has_integrity_report: msg_name == "integrity_report",
            is_challenge: msg_name == "challenge",
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::AntiCheat(hdr) => format!(
                "{} {} seq={} ({} B)",
                hdr.provider, hdr.msg_type, hdr.sequence, length
            ),
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct PlatformDissector;

impl GamePluginDissector for PlatformDissector {
    fn name(&self) -> &str {
        "platform"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::Platform
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![27018, 27019, 3074, 9302, 3478, 3479]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 8 {
            return None;
        }
        let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let channel = payload[4];
        let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let (platform, is_eos, is_xbox, is_psn) = match magic {
            0x45505300..=0x455053FF => ("eos_p2p", true, false, false),
            0x58424F00..=0x584BFFFF => ("xbox_sdv2", false, true, false),
            0x50534E00..=0x50534EFF => ("psn_rtc", false, false, true),
            _ if _src_port == 3074 || _dst_port == 3074 => ("xbox_sdv2", false, true, false),
            _ if _src_port == 27018 || _dst_port == 27018 => ("eos_p2p", true, false, false),
            _ if _src_port == 9302 || _dst_port == 9302 => ("psn_rtc", false, false, true),
            _ => return None,
        };
        Some(GamePacketInfo::Platform(PlatformPacket {
            platform: platform.into(),
            channel,
            sequence: seq,
            is_reliable: (payload.get(5).copied().unwrap_or(0) & 0x01) != 0,
            ack_count: payload.get(6).copied().unwrap_or(0),
            is_handshake: is_eos && channel < 2,
            session_id: if is_psn { Some(seq) } else { None },
            platform_rtt_ms: if is_xbox {
                Some(seq as f64 * 0.1)
            } else {
                None
            },
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Platform(hdr) => format!(
                "{} ch={} seq={} ({} B)",
                hdr.platform, hdr.channel, hdr.sequence, length
            ),
            _ => format!("Game packet ({} B)", length),
        }
    }
}

pub struct DiagnosticMetadataDissector;

impl GamePluginDissector for DiagnosticMetadataDissector {
    fn name(&self) -> &str {
        "diagnostic"
    }
    fn engine(&self) -> GameEngine {
        GameEngine::Diagnostic
    }
    fn claimed_ports(&self) -> Vec<u16> {
        vec![]
    }

    fn dissect(&self, payload: &[u8], _src_port: u16, _dst_port: u16) -> Option<GamePacketInfo> {
        if payload.len() < 4 {
            return None;
        }
        let tag = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let (source, interp_bytes, interp_ms, rep_q, srv_rtt, bw_cap, in_bps, out_bps) = match tag {
            0x4E53594E => (
                "net_sync",
                Some(u32::from_le_bytes([
                    payload.get(4).copied().unwrap_or(0),
                    payload.get(5).copied().unwrap_or(0),
                    payload.get(6).copied().unwrap_or(0),
                    payload.get(7).copied().unwrap_or(0),
                ])),
                None,
                None,
                None,
                false,
                None,
                None,
            ),
            0x50494E47 => (
                "platform_ping",
                None,
                None,
                None,
                Some(f64::from_le_bytes([
                    payload.get(4).copied().unwrap_or(0),
                    payload.get(5).copied().unwrap_or(0),
                    payload.get(6).copied().unwrap_or(0),
                    payload.get(7).copied().unwrap_or(0),
                    payload.get(8).copied().unwrap_or(0),
                    payload.get(9).copied().unwrap_or(0),
                    payload.get(10).copied().unwrap_or(0),
                    payload.get(11).copied().unwrap_or(0),
                ])),
                false,
                None,
                None,
            ),
            0x42414E44 => (
                "bandwidth",
                None,
                None,
                None,
                None,
                (payload.get(4).copied().unwrap_or(0) & 0x01) != 0,
                Some(f64::from_le_bytes([
                    payload.get(5).copied().unwrap_or(0),
                    payload.get(6).copied().unwrap_or(0),
                    payload.get(7).copied().unwrap_or(0),
                    payload.get(8).copied().unwrap_or(0),
                    payload.get(9).copied().unwrap_or(0),
                    payload.get(10).copied().unwrap_or(0),
                    payload.get(11).copied().unwrap_or(0),
                    payload.get(12).copied().unwrap_or(0),
                ])),
                None,
            ),
            _ => return None,
        };
        Some(GamePacketInfo::Diagnostic(DiagnosticMetadata {
            source: source.into(),
            interp_buffer_bytes: interp_bytes,
            interp_buffer_ms: interp_ms,
            rep_queue_depth: rep_q,
            server_reported_rtt_ms: srv_rtt,
            bandwidth_cap_requested: bw_cap,
            inbound_bps: in_bps,
            outbound_bps: out_bps,
        }))
    }

    fn summarize(&self, info: &GamePacketInfo, length: usize) -> String {
        match info {
            GamePacketInfo::Diagnostic(hdr) => format!("Diag src={} ({} B)", hdr.source, length),
            _ => format!("Game packet ({} B)", length),
        }
    }
}

/// Pre-register all built-in game plugin dissectors on a manager.
pub fn register_builtin_plugins(mgr: &mut GamePluginManager) {
    mgr.register(Box::new(UnrealIrisDissector));
    mgr.register(Box::new(UnityTransportDissector));
    mgr.register(Box::new(Source2NetmessageDissector));
    mgr.register(Box::new(GodotEnetDissector));
    mgr.register(Box::new(AntiCheatDissector));
    mgr.register(Box::new(PlatformDissector));
    mgr.register(Box::new(DiagnosticMetadataDissector));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_iris_payload(channel: u8, flags: u8, seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0] = channel;
        buf[1] = flags;
        buf[2..6].copy_from_slice(&seq.to_le_bytes());
        buf
    }

    fn make_source2_payload(msg_id: u8, tick: u32, size: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        buf[0] = msg_id;
        buf[1] = (tick >> 16) as u8;
        buf[2] = (tick >> 8) as u8;
        buf[3] = tick as u8;
        buf[4] = size;
        buf
    }

    fn make_anticheat_payload(proto: u8, msg_type: u8, seq: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 10];
        buf[0] = proto;
        buf[1] = msg_type;
        buf[2..6].copy_from_slice(&seq.to_le_bytes());
        buf
    }

    #[test]
    fn unreal_iris_dissector_matches() {
        let d = UnrealIrisDissector;
        let payload = make_iris_payload(1, 0x80, 42);
        let info = d.dissect(&payload, 7777, 0).unwrap();
        if let GamePacketInfo::Unreal(hdr) = info {
            assert_eq!(hdr.channel_index, 1);
            assert!(hdr.is_partial);
            assert_eq!(hdr.bunch_seq, 42);
        } else {
            panic!("expected Unreal");
        }
    }

    #[test]
    fn unity_utp_dissector_matches() {
        let d = UnityTransportDissector;
        let mut payload = vec![0u8; 24];
        payload[0] = 2;
        payload[4..8].copy_from_slice(&99u32.to_le_bytes());
        payload[1] = 0x01;
        payload[8..12].copy_from_slice(&7u32.to_le_bytes());
        let info = d.dissect(&payload, 14000, 0).unwrap();
        if let GamePacketInfo::Unity(hdr) = info {
            assert_eq!(hdr.pipeline_stage, 2);
            assert_eq!(hdr.sequence, 99);
            assert!(hdr.is_ghost_snapshot);
            assert_eq!(hdr.ghost_id, Some(7));
        } else {
            panic!("expected Unity");
        }
    }

    #[test]
    fn source2_dissector_matches() {
        let d = Source2NetmessageDissector;
        let payload = make_source2_payload(5, 123456, 8);
        let info = d.dissect(&payload, 27015, 0).unwrap();
        if let GamePacketInfo::Source2(hdr) = info {
            assert_eq!(hdr.msg_id, 5);
            assert_eq!(hdr.server_tick, 123456);
        } else {
            panic!("expected Source2");
        }
    }

    #[test]
    fn godot_dissector_matches() {
        let d = GodotEnetDissector;
        let mut payload = vec![0u8; 8];
        payload[0] = 0x80;
        payload[1] = 3;
        payload[2..4].copy_from_slice(&42u16.to_be_bytes());
        let info = d.dissect(&payload, 9876, 0).unwrap();
        if let GamePacketInfo::Godot(hdr) = info {
            assert!(hdr.is_reliable);
            assert_eq!(hdr.channel, 3);
            assert_eq!(hdr.sequence, 42);
        } else {
            panic!("expected Godot");
        }
    }

    #[test]
    fn anticheat_battleye_dissector_matches() {
        let d = AntiCheatDissector;
        let payload = make_anticheat_payload(0xBE, 0x00, 100);
        let info = d.dissect(&payload, 4444, 0).unwrap();
        if let GamePacketInfo::AntiCheat(hdr) = info {
            assert_eq!(hdr.provider, "battleye");
            assert!(hdr.is_challenge);
        } else {
            panic!("expected AntiCheat");
        }
    }

    #[test]
    fn anticheat_eac_dissector_matches() {
        let d = AntiCheatDissector;
        let payload = make_anticheat_payload(0xE5, 0x10, 200);
        let info = d.dissect(&payload, 5555, 0).unwrap();
        if let GamePacketInfo::AntiCheat(hdr) = info {
            assert_eq!(hdr.provider, "eac");
            assert!(hdr.has_integrity_report);
        } else {
            panic!("expected AntiCheat");
        }
    }

    #[test]
    fn platform_eos_dissector_matches() {
        let d = PlatformDissector;
        let mut payload = vec![0u8; 12];
        payload[0..4].copy_from_slice(&0x45505300u32.to_be_bytes());
        payload[4] = 1;
        let info = d.dissect(&payload, 27018, 0).unwrap();
        if let GamePacketInfo::Platform(hdr) = info {
            assert_eq!(hdr.platform, "eos_p2p");
        } else {
            panic!("expected Platform");
        }
    }

    #[test]
    fn diagnostic_net_sync_matches() {
        let d = DiagnosticMetadataDissector;
        let mut payload = vec![0u8; 12];
        payload[0..4].copy_from_slice(&0x4E53594Eu32.to_be_bytes());
        let info = d.dissect(&payload, 0, 0).unwrap();
        if let GamePacketInfo::Diagnostic(hdr) = info {
            assert_eq!(hdr.source, "net_sync");
        } else {
            panic!("expected Diagnostic");
        }
    }

    #[test]
    fn manager_handles_all_plugins() {
        let mut mgr = GamePluginManager::new();
        register_builtin_plugins(&mut mgr);
        assert_eq!(mgr.dissectors().count(), 7);

        let payload = make_iris_payload(0, 0, 100);
        let result = mgr.dissect_packet(&payload, "10.0.0.1", "10.0.0.2", 7777, 7777);
        assert!(matches!(result, Some(GamePacketInfo::Unreal(_))));
    }

    #[test]
    fn manager_diagnostics_empty_by_default() {
        let mut mgr = GamePluginManager::new();
        mgr.register(Box::new(UnrealIrisDissector));
        let payload = make_iris_payload(0, 0, 1);
        mgr.dissect_packet(&payload, "10.0.0.1", "10.0.0.2", 7777, 7777);
        assert!(mgr.diagnose("10.0.0.1", "10.0.0.2", 7777, 7777).is_empty());
    }

    #[test]
    fn load_manifest_from_text() {
        let mut mgr = GamePluginManager::new();
        let toml_path = std::env::temp_dir().join("test_plugin.toml");
        std::fs::write(
            &toml_path,
            r#"
[plugin]
name = "test-plugin"
version = "0.1.0"
author = "test"
[[protocol]]
name = "TestProto"
transport = "udp"
ports = [12345]
"#,
        )
        .unwrap();
        mgr.load_manifest(&toml_path).unwrap();
        assert!(mgr.manifests().contains_key("test-plugin"));
        std::fs::remove_file(&toml_path).ok();
    }
}
