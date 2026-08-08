// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use netscope_core::alerting::{Alert, AlertEngine, AlertRule, RuleTrigger};
use netscope_core::capture::{CaptureEngine, CaptureOptions, StopConditions};
use netscope_core::config::Config;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;
use netscope_core::remote::RemoteSpec;
use netscope_core::rotate::RingBufferOptions;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

pub struct CaptureState {
    pub engine: Option<CaptureEngine>,
    pub running: AtomicBool,
    pub packet_buffer: Vec<Packet>,
    pub names: NameCache,
    pub _packet_count: u64,
    pub alert_engine: Option<AlertEngine>,
}

#[derive(Serialize, Clone)]
struct AlertInfo {
    timestamp: String,
    rule_name: String,
    severity: String,
    msg: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    mitre_attack: Option<String>,
    kill_chain: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    /// "ethernet" | "loopback" | "usb" | "bluetooth" | "can" — lets the UI
    /// badge hardware-bus capture sources.
    pub kind: String,
}

#[derive(Serialize, Clone)]
struct PacketInfo {
    timestamp: String,
    /// Milliseconds since the Unix epoch (UTC) — lets the frontend offer
    /// alternate time display formats (date+time, relative-to-capture-start)
    /// without reformatting on the backend for each one.
    epoch_ms: i64,
    src_addr: Option<String>,
    dst_addr: Option<String>,
    /// Hostname learned for the source IP, if any (passive DNS).
    src_host: Option<String>,
    dst_host: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: String,
    length: usize,
    summary: String,
    /// Plain-language one-liner about what this packet is doing.
    explanation: String,
    raw: Vec<u8>,
}

/// Build the frontend packet view, resolving hostnames from the cache.
fn packet_to_info(pkt: &Packet, names: &NameCache) -> PacketInfo {
    let src_host = pkt
        .src_addr
        .and_then(|a| names.name_for(a).map(|s| s.to_string()));
    let dst_host = pkt
        .dst_addr
        .and_then(|a| names.name_for(a).map(|s| s.to_string()));
    PacketInfo {
        raw: pkt.data.to_vec(),
        timestamp: pkt.timestamp.format("%H:%M:%S%.3f").to_string(),
        epoch_ms: pkt.timestamp.timestamp_millis(),
        src_addr: pkt.src_addr.map(|a| a.to_string()),
        dst_addr: pkt.dst_addr.map(|a| a.to_string()),
        src_host,
        dst_host,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        protocol: pkt.protocol.to_string(),
        length: pkt.length,
        summary: pkt.summary.clone(),
        explanation: netscope_core::education::explain_packet(pkt).to_string(),
    }
}

#[derive(Serialize, Clone)]
pub struct LessonInfo {
    pub protocol: String,
    pub title: String,
    pub summary: String,
    pub body: String,
    pub look_for: String,
}

#[derive(Serialize, Clone)]
pub struct TermInfo {
    pub term: String,
    pub meaning: String,
}

#[tauri::command]
fn get_lessons() -> Vec<LessonInfo> {
    // Every protocol that has a lesson of its own — about 1,400 of them.
    // This used to be a hand-written array of 53 `("DNS", Protocol::Dns)`
    // pairs, so the Learn tab showed a twenty-fifth of what `education.rs`
    // contains and silently stopped growing when protocols were added.
    netscope_core::education::protocols_with_lessons()
        .into_iter()
        .map(|p| {
            let l = netscope_core::education::lesson(p);
            LessonInfo {
                protocol: p.display_name().to_string(),
                title: l.title.to_string(),
                summary: l.summary.to_string(),
                body: l.body.to_string(),
                look_for: l.look_for.to_string(),
            }
        })
        .collect()
}

#[derive(Serialize, Clone)]
pub struct RiskInfo {
    pub severity: String,
    pub headline: String,
    pub detail: String,
    pub mitigation: String,
    pub reference: String,
}

/// The documented security risk of one protocol, by its display name.
///
/// Fetched when a packet is selected rather than attached to every `PacketInfo`:
/// the notes run to a few hundred bytes each and a batch carries thousands of
/// packets, so shipping them per packet would cost far more than it returns.
///
/// `None` is the honest and common answer — most protocols have nothing
/// specific to say, and the panel shows nothing rather than filler.
#[tauri::command]
fn get_protocol_risk(protocol: String) -> Option<RiskInfo> {
    use netscope_core::models::Protocol;
    let proto = Protocol::ALL
        .iter()
        .find(|p| p.display_name() == protocol)?;
    let r = netscope_core::protocol_risk::risk(proto)?;
    Some(RiskInfo {
        severity: r.severity.label().to_string(),
        headline: r.headline.to_string(),
        detail: r.detail.to_string(),
        mitigation: r.mitigation.to_string(),
        reference: r.reference.to_string(),
    })
}

#[derive(Serialize, Clone)]
pub struct KeyLogStatus {
    /// Connections the loaded secrets can decrypt.
    pub sessions: usize,
    /// Secret lines accepted by this load.
    pub added: usize,
    /// Lines that were neither comments nor parseable.
    pub rejected: usize,
}

/// Load `SSLKEYLOGFILE` contents so TLS sessions can be decrypted.
///
/// The text is passed in rather than a path: the UI accepts a drag-and-drop,
/// and the browser hands over file *contents*. It also keeps this command from
/// being a way to make the app read an arbitrary file off disk.
///
/// Loads merge — see `tls_keylog::KeyLog::merge_from` for why.
#[tauri::command]
fn tls_keylog_load(text: String) -> KeyLogStatus {
    let stats = netscope_core::tls_keylog::load(&text);
    KeyLogStatus {
        sessions: netscope_core::tls_keylog::session_count(),
        added: stats.secrets,
        rejected: stats.rejected,
    }
}

/// Forget every loaded secret. These decrypt real traffic, so being able to
/// drop them without restarting the app is part of handling them responsibly.
#[tauri::command]
fn tls_keylog_clear() -> KeyLogStatus {
    netscope_core::tls_keylog::clear();
    KeyLogStatus {
        sessions: 0,
        added: 0,
        rejected: 0,
    }
}

#[tauri::command]
fn tls_keylog_status() -> KeyLogStatus {
    KeyLogStatus {
        sessions: netscope_core::tls_keylog::session_count(),
        added: 0,
        rejected: 0,
    }
}

#[tauri::command]
fn get_glossary() -> Vec<TermInfo> {
    netscope_core::education::glossary()
        .iter()
        .map(|t| TermInfo {
            term: t.term.to_string(),
            meaning: t.meaning.to_string(),
        })
        .collect()
}

// ---- GeoIP (offline MMDB) --------------------------------------------------
//
// An offline MaxMind database (.mmdb — e.g. the free GeoLite2-City) resolves
// IP locations locally, with no network calls. This is the only GeoIP path:
// netscope makes no outbound requests at all, so locations work offline and
// stay private.

#[derive(Default)]
pub struct GeoDbState {
    pub reader: Option<maxminddb::Reader<Vec<u8>>>,
    pub path: String,
}

#[derive(Serialize, Clone)]
pub struct GeoDbInfo {
    pub path: String,
    /// e.g. "GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN".
    pub db_type: String,
    /// Database build time, seconds since the Unix epoch.
    pub build_epoch: u64,
}

#[tauri::command]
fn geoip_load_db(path: String, state: State<'_, Mutex<GeoDbState>>) -> Result<GeoDbInfo, String> {
    let reader = maxminddb::Reader::open_readfile(&path)
        .map_err(|e| format!("Cannot open GeoIP database: {e}"))?;
    let info = GeoDbInfo {
        path: path.clone(),
        db_type: reader.metadata.database_type.clone(),
        build_epoch: reader.metadata.build_epoch,
    };
    let mut guard = state.lock().unwrap();
    guard.reader = Some(reader);
    guard.path = path;
    Ok(info)
}

#[tauri::command]
fn geoip_unload_db(state: State<'_, Mutex<GeoDbState>>) {
    let mut guard = state.lock().unwrap();
    guard.reader = None;
    guard.path.clear();
}

#[derive(Serialize, Clone, Default)]
pub struct GeoLookup {
    pub country: Option<String>,
    pub code: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// English name from an MMDB localized-names record (any locale as fallback).
pub fn english_name(names: &maxminddb::geoip2::Names) -> Option<String> {
    names
        .english
        .or(names.german)
        .or(names.spanish)
        .or(names.french)
        .or(names.japanese)
        .or(names.brazilian_portuguese)
        .or(names.russian)
        .or(names.simplified_chinese)
        .map(str::to_string)
}

fn geoip_lookup_inner(geo: &GeoDbState, ip: &str) -> Result<Option<GeoLookup>, String> {
    use maxminddb::geoip2;
    let addr: std::net::IpAddr = ip.parse().map_err(|e| format!("Invalid IP: {e}"))?;
    let Some(reader) = geo.reader.as_ref() else {
        return Ok(None);
    };
    let result = reader
        .lookup(addr)
        .map_err(|e| format!("GeoIP lookup failed: {e}"))?;
    if reader.metadata.database_type.contains("ASN") {
        let Some(a) = result
            .decode::<geoip2::Asn>()
            .map_err(|e| format!("GeoIP lookup failed: {e}"))?
        else {
            return Ok(None);
        };
        return Ok(Some(GeoLookup {
            asn: a.autonomous_system_number,
            org: a.autonomous_system_organization.map(str::to_string),
            ..Default::default()
        }));
    }
    let Some(c) = result
        .decode::<geoip2::City>()
        .map_err(|e| format!("GeoIP lookup failed: {e}"))?
    else {
        return Ok(None);
    };
    Ok(Some(GeoLookup {
        country: english_name(&c.country.names),
        code: c.country.iso_code.map(str::to_string),
        city: english_name(&c.city.names),
        region: c.subdivisions.first().and_then(|s| english_name(&s.names)),
        ..Default::default()
    }))
}

#[tauri::command]
fn geoip_lookup(
    ip: String,
    state: State<'_, Mutex<GeoDbState>>,
) -> Result<Option<GeoLookup>, String> {
    let guard = state.lock().unwrap();
    geoip_lookup_inner(&guard, &ip)
}

// ---- Layered configuration & plugins (ROADMAP §2.3 / §2.4) -----------------
//
// ~/.netscope/config.toml (plus optional profiles) is loaded once at startup:
// it can point at an offline GeoIP database, enable the plugins directory and
// name the active profile. Declarative protocol plugins (*.toml) are loaded
// into netscope-core's registry so the dissectors pick them up.

pub struct ConfigState {
    pub config: Config,
    pub plugins_loaded: usize,
    pub plugin_errors: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct AppConfigInfo {
    /// The config directory (~/.netscope or $NETSCOPE_CONFIG_DIR).
    pub dir: String,
    pub active_profile: Option<String>,
    pub profiles: Vec<String>,
    pub plugins_enabled: bool,
    pub plugins_dir: String,
    pub plugins_loaded: usize,
    pub plugin_errors: Vec<String>,
    /// Offline GeoIP database auto-loaded from the config, if any.
    pub geoip_db: Option<GeoDbInfo>,
}

fn config_info(cfg: &ConfigState, geo: &GeoDbState) -> AppConfigInfo {
    AppConfigInfo {
        dir: cfg.config.dir().display().to_string(),
        active_profile: cfg.config.active_profile().map(str::to_string),
        profiles: cfg.config.profiles(),
        plugins_enabled: cfg.config.plugins.enabled,
        plugins_dir: cfg.config.plugins_dir().display().to_string(),
        plugins_loaded: cfg.plugins_loaded,
        plugin_errors: cfg.plugin_errors.clone(),
        geoip_db: geo.reader.as_ref().map(|r| GeoDbInfo {
            path: geo.path.clone(),
            db_type: r.metadata.database_type.clone(),
            build_epoch: r.metadata.build_epoch,
        }),
    }
}

#[tauri::command]
fn get_app_config(
    cfg: State<'_, Mutex<ConfigState>>,
    geo: State<'_, Mutex<GeoDbState>>,
) -> AppConfigInfo {
    let cfg = cfg.lock().unwrap();
    let geo = geo.lock().unwrap();
    config_info(&cfg, &geo)
}

#[derive(Serialize, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub transport: String,
    pub ports: Vec<u16>,
    pub description: String,
}

#[tauri::command]
fn list_plugins() -> Vec<PluginInfo> {
    netscope_core::plugins::installed()
        .into_iter()
        .map(|p| PluginInfo {
            name: p.name,
            transport: match p.transport {
                netscope_core::plugins::TransportKind::Tcp => "tcp".into(),
                netscope_core::plugins::TransportKind::Udp => "udp".into(),
            },
            ports: p.ports,
            description: p.description,
        })
        .collect()
}

/// Re-read config.toml and the plugins directory, so edits apply without an
/// app restart. Returns the refreshed config summary.
#[tauri::command]
fn reload_plugins(
    cfg: State<'_, Mutex<ConfigState>>,
    geo: State<'_, Mutex<GeoDbState>>,
) -> AppConfigInfo {
    let mut cfg = cfg.lock().unwrap();
    cfg.config = Config::load();
    let outcome = netscope_core::plugins::load_from_config(&cfg.config);
    cfg.plugins_loaded = outcome.loaded;
    cfg.plugin_errors = outcome.errors;
    let geo = geo.lock().unwrap();
    config_info(&cfg, &geo)
}

/// Capture-pipeline counters (ROADMAP §2.1): frames received off the wire,
/// dropped because the ring was full, and dissected. `None` when no capture
/// has been started.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct CaptureStats {
    pub received: u64,
    pub dropped: u64,
    pub dissected: u64,
}

#[tauri::command]
fn get_capture_stats(state: State<'_, Mutex<CaptureState>>) -> Option<CaptureStats> {
    let guard = state.lock().ok()?;
    let stats = guard.engine.as_ref()?.pipeline_stats()?;
    Some(CaptureStats {
        received: stats.received,
        dropped: stats.dropped,
        dissected: stats.dissected,
    })
}

#[tauri::command]
fn is_elevated() -> bool {
    netscope_core::firewall::is_elevated()
}

/// Restart netscope with Administrator rights.
///
/// Capture needs elevation on Windows, so the UI offers this as one click
/// rather than making the user find the executable themselves. The elevated
/// instance is launched through PowerShell's `-Verb RunAs` — that is what
/// raises the UAC prompt — and this process then leaves through Tauri's own
/// exit so the capture pipeline and any open capture file close cleanly.
#[tauri::command]
fn relaunch_elevated(app: AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        let current_exe =
            std::env::current_exe().map_err(|e| format!("Cannot locate the application: {e}"))?;

        // Doubling is how a single quote escapes inside a PowerShell literal.
        let path = current_exe.to_string_lossy().replace('\'', "''");
        // Without `-ErrorAction Stop` a declined UAC prompt still exits 0, and
        // we would quit the running instance without a replacement.
        let status = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Start-Process -FilePath '{path}' -Verb RunAs -ErrorAction Stop"),
            ])
            .status()
            .map_err(|e| e.to_string())?;

        if !status.success() {
            return Err("Administrator rights were not granted.".into());
        }
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Automatic elevation is only available on Windows — start netscope with sudo.".into())
    }
}

/// How many protocols the build recognises.
///
/// Read from the registry rather than written down in the UI, because the
/// registry is the only place that knows — a number typed into the frontend
/// starts drifting the moment a protocol is added.
#[tauri::command]
fn protocol_count() -> usize {
    // `PRODUCED`, not `ALL`: the table also declares protocols no dissector
    // assigns, and counting those would advertise coverage that does not exist.
    netscope_core::models::Protocol::produced().len()
}

/// What the frontend needs to know about a protocol beyond its name.
#[derive(serde::Serialize)]
pub struct ProtocolMeta {
    /// How it groups into flows: `tcp`, `udp`, `icmp`, `arp` or `other`.
    pub transport: &'static str,
    /// How specific it is as a label for a whole flow — the highest-ranked
    /// packet in a flow is the one that names it.
    pub rank: u8,
}

/// The whole registry, keyed by the display name the frontend already receives.
///
/// The frontend used to answer both questions from lists written into its own
/// source, which covered around forty protocols out of the two and a half
/// thousand here. Everything absent fell to "other" and rank 1, so a flow
/// carrying NGAP or PROFINET — both rank 3, both meant to name their flow —
/// was labelled TCP instead. The registry is the one place that knows, so it
/// is the one place this comes from.
#[tauri::command]
fn protocol_table() -> std::collections::HashMap<String, ProtocolMeta> {
    use netscope_core::models::Protocol;
    use netscope_core::registry::TransportClass;
    Protocol::ALL
        .iter()
        .filter(|p| !p.display_name().is_empty())
        .map(|p| {
            let transport = match p.transport_class() {
                TransportClass::Tcp => "tcp",
                TransportClass::Udp => "udp",
                TransportClass::Icmp => "icmp",
                TransportClass::Arp => "arp",
                TransportClass::Other => "other",
            };
            (
                p.display_name().to_string(),
                ProtocolMeta {
                    transport,
                    rank: p.rank(),
                },
            )
        })
        .collect()
}

#[tauri::command]
fn list_blocked() -> Vec<String> {
    netscope_core::firewall::blocked_ips()
        .into_iter()
        .map(|ip| ip.to_string())
        .collect()
}

#[tauri::command]
fn block_ip(ip: String) -> Result<(), String> {
    let addr = ip
        .parse()
        .map_err(|_| format!("'{ip}' is not a valid IP address"))?;
    netscope_core::firewall::block(addr).map_err(|e| e.to_string())
}

#[tauri::command]
fn unblock_ip(ip: String) -> Result<(), String> {
    let addr = ip
        .parse()
        .map_err(|_| format!("'{ip}' is not a valid IP address"))?;
    netscope_core::firewall::unblock(addr).map_err(|e| e.to_string())
}

#[derive(Serialize, Clone, Debug)]
pub struct ReplayResult {
    pub sent: usize,
    pub response: Vec<u8>,
    pub truncated: bool,
    pub elapsed_ms: u64,
    pub note: String,
}

/// Replay (resend) an application-layer payload to a target host, Repeater-style,
/// and return whatever the target sends back. Opens a fresh TCP/UDP socket — this
/// is a deliberate, user-initiated action that sends real data onto the network,
/// the same thing Packet Sender or Burp Repeater do. Bounded by connect/read
/// timeouts and a 64 KiB response cap so it can't hang or flood the UI.
#[tauri::command]
fn replay_packet(
    host: String,
    port: u16,
    protocol: String,
    data: Vec<u8>,
    timeout_ms: Option<u64>,
) -> Result<ReplayResult, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
    use std::time::{Duration, Instant};

    const MAX_RESPONSE: usize = 64 * 1024;
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(3000).clamp(100, 30_000));

    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("Could not resolve {host}:{port} — {e}"))?
        .next()
        .ok_or_else(|| format!("No address found for {host}:{port}"))?;

    let started = Instant::now();
    let mut response = Vec::new();
    let mut truncated = false;

    match protocol.to_lowercase().as_str() {
        "tcp" => {
            let mut stream = TcpStream::connect_timeout(&addr, timeout)
                .map_err(|e| format!("Connect failed: {e}"))?;
            stream.set_write_timeout(Some(timeout)).ok();
            stream.set_read_timeout(Some(timeout)).ok();
            stream
                .write_all(&data)
                .map_err(|e| format!("Send failed: {e}"))?;
            // Read until timeout, EOF, or cap.
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if response.len() + n > MAX_RESPONSE {
                            response.extend_from_slice(&buf[..MAX_RESPONSE - response.len()]);
                            truncated = true;
                            break;
                        }
                        response.extend_from_slice(&buf[..n]);
                    }
                    Err(_) => break, // timeout / connection reset ends the read
                }
            }
        }
        "udp" => {
            let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Socket error: {e}"))?;
            sock.set_read_timeout(Some(timeout)).ok();
            sock.connect(addr)
                .map_err(|e| format!("Connect failed: {e}"))?;
            sock.send(&data).map_err(|e| format!("Send failed: {e}"))?;
            let mut buf = [0u8; 65535];
            if let Ok(n) = sock.recv(&mut buf) {
                response.extend_from_slice(&buf[..n.min(MAX_RESPONSE)]);
                truncated = n > MAX_RESPONSE;
            }
        }
        other => return Err(format!("Unsupported protocol: {other}")),
    }

    let note = if response.is_empty() {
        "Sent, but no response before timeout (normal for fire-and-forget or filtered targets)."
            .into()
    } else {
        String::new()
    };
    Ok(ReplayResult {
        sent: data.len(),
        response,
        truncated,
        elapsed_ms: started.elapsed().as_millis() as u64,
        note,
    })
}

pub trait InterfaceProvider: Send + Sync {
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, String>;
}

pub struct SystemInterfaceProvider;

impl InterfaceProvider for SystemInterfaceProvider {
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, String> {
        let devices = netscope_core::capture::list_interfaces().map_err(|e| e.to_string())?;
        let mut out: Vec<InterfaceInfo> = devices
            .into_iter()
            .map(|d| {
                let kind = netscope_core::capture::interface_kind(&d)
                    .as_str()
                    .to_string();
                InterfaceInfo {
                    name: d.name,
                    description: d.desc.unwrap_or_default(),
                    kind,
                }
            })
            .collect();
        for (value, display) in netscope_core::remote::usbpcap_interfaces() {
            out.push(InterfaceInfo {
                name: value,
                description: display,
                kind: "usb".into(),
            });
        }
        Ok(out)
    }
}

pub struct MockInterfaceProvider {
    pub interfaces: Vec<InterfaceInfo>,
}

impl InterfaceProvider for MockInterfaceProvider {
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>, String> {
        Ok(self.interfaces.clone())
    }
}

pub fn list_interfaces_with_provider(
    provider: &dyn InterfaceProvider,
) -> Result<Vec<InterfaceInfo>, String> {
    provider.list_interfaces()
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    list_interfaces_with_provider(&SystemInterfaceProvider)
}

#[derive(Serialize, Clone, Debug)]
pub struct NeighbourInfo {
    pub ip: String,
    pub mac: String,
}

/// Sweep the local IPv4 subnet of `interface` and return the neighbours the OS
/// resolved. `"__all__"` (or an empty string) means "pick the interface with a
/// routable IPv4", which is what the toolbar's default selection maps to.
#[tauri::command]
fn arp_scan(interface: String) -> Result<Vec<NeighbourInfo>, String> {
    let found = netscope_core::discover::arp_scan_interface(&interface)?;
    Ok(found
        .into_iter()
        .map(|n| NeighbourInfo {
            ip: n.ip,
            mac: n.mac,
        })
        .collect())
}

/// Optional capture knobs sent from the frontend's Capture-options dialog.
/// All fields default to off, so an older frontend (or a plain start) works
/// unchanged.
#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
struct CaptureOptionsArg {
    /// Autostop: stop after this many seconds / packets / captured kilobytes.
    stop_duration_secs: Option<u64>,
    stop_packets: Option<u64>,
    stop_filesize_kb: Option<u64>,
    /// Write the capture to this pcap file while it runs.
    output_path: Option<String>,
    /// Ring buffer for `output_path` (Wireshark -b): rotate by size/time,
    /// keep at most `ring_files` files.
    ring_filesize_kb: Option<u64>,
    ring_duration_secs: Option<u64>,
    ring_files: Option<usize>,
}

impl CaptureOptionsArg {
    fn to_options(&self, filter: Option<String>, monitor: bool) -> Result<CaptureOptions, String> {
        let ring = if self.ring_filesize_kb.is_some()
            || self.ring_duration_secs.is_some()
            || self.ring_files.is_some()
        {
            let ring = RingBufferOptions {
                filesize_kb: self.ring_filesize_kb,
                duration_secs: self.ring_duration_secs,
                files: self.ring_files,
            };
            if !ring.rotates() {
                return Err("A ring buffer needs a file size or duration to rotate on.".to_string());
            }
            if self.output_path.is_none() {
                return Err("A ring buffer needs an output file to write to.".to_string());
            }
            Some(ring)
        } else {
            None
        };
        Ok(CaptureOptions {
            bpf_filter: filter,
            output_path: self.output_path.clone(),
            monitor,
            stop: StopConditions {
                duration_secs: self.stop_duration_secs,
                packets: self.stop_packets,
                bytes: self.stop_filesize_kb.map(|kb| kb.saturating_mul(1024)),
            },
            ring,
            ..Default::default()
        })
    }
}

/// Store the started engine and spawn the packet forwarder. Emits
/// `capture-stopped` when the stream ends on its own (autostop limit hit,
/// remote side gone) so the UI can flip back to idle.
fn adopt_capture(
    app: &AppHandle,
    state: &State<'_, Mutex<CaptureState>>,
    capture: CaptureEngine,
    packet_rx: crossbeam_channel::Receiver<Packet>,
) -> Result<(), String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    guard.engine = Some(capture);
    guard.running.store(true, Ordering::SeqCst);
    guard.packet_buffer.clear();
    guard.names.clear();
    guard.alert_engine = Some(AlertEngine::new(default_alert_rules()));
    drop(guard);

    // The notifier and the escalation ticker are app-lifetime, built once at
    // startup. They used to be created here, so every capture start spawned
    // another ticker thread that looped forever alongside the previous one.
    let notifier = app.state::<NotifierState>().inner().tx.clone();

    let app_handle = app.clone();
    std::thread::spawn(move || {
        loop {
            match packet_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(pkt) => {
                    let (info, alerts) =
                        if let Ok(mut g) = app_handle.state::<Mutex<CaptureState>>().lock() {
                            g.names.observe(&pkt);
                            let info = packet_to_info(&pkt, &g.names);
                            let alerts = g
                                .alert_engine
                                .as_mut()
                                .map(|ae| ae.check_packet(&pkt, None))
                                .unwrap_or_default();
                            g.packet_buffer.push(pkt);
                            if g.packet_buffer.len() > 100_000 {
                                g.packet_buffer.drain(..50_000);
                            }
                            (info, alerts)
                        } else {
                            (packet_to_info(&pkt, &NameCache::new()), vec![])
                        };
                    let _ = app_handle.emit("packet", info);
                    for a in alerts {
                        let _ = app_handle.emit("alert", alert_to_info(&a));
                        // Start the clock before handing the alert off, so an
                        // unacknowledged alert climbs the chain even if every
                        // notification channel is failing.
                        if let Ok(mut esc) = app_handle.state::<Mutex<EscalationState>>().lock() {
                            if let Some(engine) = esc.engine.as_mut() {
                                engine.trigger_alert_escalation(
                                    format!("{}|{}", a.timestamp, a.rule_name),
                                    a.rule_name.clone(),
                                    a.msg.clone(),
                                );
                            }
                        }
                        if let Some(tx) = &notifier {
                            let _ = tx.send(Dispatch::Alert(a));
                        }
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = app_handle.emit("capture-stopped", ());
    });

    Ok(())
}

fn alert_to_info(a: &Alert) -> AlertInfo {
    AlertInfo {
        timestamp: a.timestamp.clone(),
        rule_name: a.rule_name.clone(),
        severity: a.severity.clone(),
        msg: a.msg.clone(),
        src_ip: a.src_ip.clone(),
        dst_ip: a.dst_ip.clone(),
        mitre_attack: a.mitre_attack.clone(),
        kill_chain: a.kill_chain.clone(),
    }
}

#[tauri::command]
fn get_alert_rules() -> Vec<AlertRule> {
    default_alert_rules()
}

/// Start a thread that delivers alerts to every configured channel.
///
/// Returns `None` when nothing is configured, so the common case costs no
/// thread and no queue. Delivery is blocking I/O — SMTP handshakes, HTTPS
/// posts — so it must not happen on the capture loop that produces the alerts;
/// the channel between them is what keeps a slow or unreachable endpoint from
/// stalling capture. Failures are reported to the UI rather than retried:
/// a channel that is down stays down, and silently swallowing that is exactly
/// the behaviour this whole view exists to get rid of.
fn spawn_alert_notifier(app: &AppHandle) -> Option<crossbeam_channel::Sender<Dispatch>> {
    let (settings, escalation_on) = {
        let cfg = app.state::<Mutex<ConfigState>>();
        let guard = cfg.lock().ok()?;
        (
            guard.config.notifications.clone(),
            guard.config.escalation.enabled && !guard.config.escalation.oncall.is_empty(),
        )
    };

    let targets: Vec<String> = notification_channels(&settings)
        .into_iter()
        .filter(|c| c.configured && c.available)
        .map(|c| c.id)
        .collect();
    // Escalation reaches PagerDuty/Opsgenie/VictorOps through the on-call
    // integration key rather than a `[notifications]` setting, so it needs this
    // thread even when no ordinary channel is configured.
    if targets.is_empty() && !escalation_on {
        return None;
    }

    let engine = netscope_core::notifications::NotificationEngine::new(settings.to_engine_config());
    let (tx, rx) = crossbeam_channel::unbounded::<Dispatch>();
    let app_handle = app.clone();

    std::thread::spawn(move || {
        for item in rx {
            match item {
                Dispatch::Alert(alert) => {
                    let msg = format!("[{}] {}: {}", alert.severity, alert.rule_name, alert.msg);
                    for id in &targets {
                        let sent = match id.as_str() {
                            "syslog" => engine.send_syslog(&msg),
                            "email" => engine.send_email(&alert.rule_name, &msg),
                            "slack" => engine.send_slack(&msg, "{}"),
                            "telegram" => engine.send_telegram(&msg),
                            "winevent" => engine.write_windows_event_log(&msg),
                            _ => Ok(()),
                        };
                        report_delivery(&app_handle, id, sent);
                    }
                }
                // One escalation step goes to the one channel its chain names.
                Dispatch::Escalation(notice) => {
                    let channel = notice.channel.clone();
                    report_delivery(&app_handle, &channel, engine.send_escalation(&notice));
                }
            }
        }
    });

    Some(tx)
}

#[derive(Serialize, Clone)]
struct NotificationError {
    channel: String,
    error: String,
}

/// The app-lifetime handle on the notifier queue.
///
/// Built once at startup so the delivery thread and the escalation ticker
/// outlive any single capture, and so starting a capture twice cannot spawn a
/// second copy of either.
struct NotifierState {
    tx: Option<crossbeam_channel::Sender<Dispatch>>,
}

/// What the notifier thread delivers.
///
/// Alerts fan out to every configured channel; an escalation step goes to the
/// single channel its rung of the chain names. Both travel the same queue so
/// there is one delivery path, and therefore one place that reports failure.
enum Dispatch {
    Alert(Alert),
    Escalation(netscope_core::escalation::EscalationNotice),
}

/// Surface a delivery failure to the UI. Success is silent.
fn report_delivery(app: &AppHandle, channel: &str, result: Result<(), String>) {
    if let Err(error) = result {
        let _ = app.emit(
            "notification-error",
            NotificationError {
                channel: channel.to_string(),
                error,
            },
        );
    }
}

// ---- Escalation ------------------------------------------------------------
//
// `escalation.rs` had every piece of this — the L1→L2→L3→CISO chain, the
// weekly rotation, the on-call API calls — and nothing ever constructed an
// engine, so the SOC card said "no escalation rules configured" no matter what
// was in the config. These wire it to real alerts and report its real state.

pub struct EscalationState {
    /// `None` when `[escalation] enabled` is false, which is the default:
    /// escalation pages people, so it never starts by itself.
    pub engine: Option<netscope_core::escalation::EscalationEngine>,
}

/// Build the engine from config, or `None` when escalation is switched off.
fn build_escalation_engine(
    cfg: &netscope_core::config::Escalation,
) -> Option<netscope_core::escalation::EscalationEngine> {
    // An empty rotation would escalate happily and page nobody, which looks
    // exactly like working escalation until the night it matters. Treat it as
    // not configured so the UI can say so.
    if !cfg.enabled || cfg.oncall.is_empty() {
        return None;
    }
    let mut engine = netscope_core::escalation::EscalationEngine::new(cfg.shift_rotations());

    // Custom step timings replace the built-in 15/30/60-minute chain, keeping
    // each step's level and channel. Extra entries are ignored rather than
    // inventing levels the engine has no name for.
    if !cfg.step_minutes.is_empty() {
        for (step, mins) in engine
            .default_policy
            .chain
            .iter_mut()
            .zip(cfg.step_minutes.iter())
        {
            step.wait_duration_secs = mins.saturating_mul(60);
        }
    }
    Some(engine)
}

#[derive(Serialize, Clone)]
pub struct OnCallInfo {
    pub name: String,
    pub email: String,
    pub phone: String,
}

#[derive(Serialize, Clone)]
pub struct ActiveEscalationInfo {
    pub alert_id: String,
    pub rule_name: String,
    pub alert_msg: String,
    /// "Escalating" | "Acknowledged" | "Resolved".
    pub status: String,
    /// Which rung of the chain it has reached, as a name the UI can show.
    pub level: String,
    /// Seconds since the alert first escalated — the number that decides
    /// whether anyone is actually responding.
    pub age_secs: i64,
}

#[derive(Serialize, Clone)]
pub struct EscalationStatus {
    pub enabled: bool,
    /// Why it is off, when it is. Empty when running.
    pub reason: String,
    pub iso_week: u32,
    pub primary: Option<OnCallInfo>,
    pub backup: Option<OnCallInfo>,
    pub steps: Vec<String>,
    pub active: Vec<ActiveEscalationInfo>,
}

/// Advance the escalation chain on a timer.
///
/// The chain is time-based — a step fires when nobody acknowledged within its
/// wait — so something has to ask. Doing it from the packet loop would tie
/// escalation to traffic arriving, which is backwards: the case that matters
/// most is an alert on a link that then goes quiet. A 15-second tick is far
/// finer than the minutes-long steps it drives.
fn spawn_escalation_ticker(app: &AppHandle, notifier: Option<crossbeam_channel::Sender<Dispatch>>) {
    let app_handle = app.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(15));
            let state = app_handle.state::<Mutex<EscalationState>>();
            let notices = {
                let Ok(mut guard) = state.lock() else { break };
                match guard.engine.as_mut() {
                    Some(engine) => engine.process_escalations(chrono::Utc::now()),
                    // Escalation is off; nothing to do, but keep the thread so
                    // it starts working if it is switched on and reloaded.
                    None => Vec::new(),
                }
            };
            for notice in notices {
                // Tell the UI a rung came due…
                let _ = app_handle.emit("escalation", &notice);
                // …and actually page the on-call. Without this the chain only
                // ever produced text: the engine's own delivery had no arm for
                // Slack or Email, so L1 and L2 reached nobody.
                match &notifier {
                    Some(tx) => {
                        let _ = tx.send(Dispatch::Escalation(notice));
                    }
                    None => report_delivery(
                        &app_handle,
                        &notice.channel,
                        Err("Escalation fired but no delivery channel is configured".into()),
                    ),
                }
            }
        }
    });
}

#[tauri::command]
/// The status shown when there is no engine, which has two different causes.
///
/// `build_escalation_engine` returns `None` both when escalation is switched
/// off and when it is switched on with an empty `[[escalation.oncall]]`. Those
/// look identical from here and mean opposite things to the reader: one is "you
/// have not turned this on", the other is "you turned it on and it will page
/// nobody". Getting the two messages the wrong way round tells an operator
/// their rota is fine when it is empty.
fn escalation_off(configured_enabled: bool, iso_week: u32) -> EscalationStatus {
    EscalationStatus {
        enabled: false,
        reason: if configured_enabled {
            "No one is listed under [[escalation.oncall]].".into()
        } else {
            "Set [escalation] enabled = true to turn this on.".into()
        },
        iso_week,
        primary: None,
        backup: None,
        steps: Vec::new(),
        active: Vec::new(),
    }
}

/// The open escalations, worst first.
///
/// "Worst" is oldest: the alert nobody has answered longest is the one about to
/// go past the top of the chain. An escalation that has run off the end of the
/// chain has no step to name, and is reported as `Top` rather than dropped —
/// that is exactly the row an operator needs to see.
pub fn active_escalations(
    engine: &netscope_core::escalation::EscalationEngine,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<ActiveEscalationInfo> {
    let mut active: Vec<ActiveEscalationInfo> = engine
        .active_escalations
        .values()
        .map(|e| ActiveEscalationInfo {
            alert_id: e.alert_id.clone(),
            rule_name: e.rule_name.clone(),
            alert_msg: e.alert_msg.clone(),
            status: e.status.clone(),
            level: engine
                .default_policy
                .chain
                .get(e.current_step_index)
                .map(|s| format!("{:?}", s.level))
                // Past the last rung there is nowhere left to escalate to.
                .unwrap_or_else(|| "Top".into()),
            age_secs: now.signed_duration_since(e.start_time).num_seconds(),
        })
        .collect();
    active.sort_by_key(|e| std::cmp::Reverse(e.age_secs));
    active
}

#[tauri::command]
fn get_escalation_status(
    esc: State<'_, Mutex<EscalationState>>,
    cfg: State<'_, Mutex<ConfigState>>,
) -> EscalationStatus {
    use chrono::{Datelike, Utc};

    let now = Utc::now();
    let iso_week = now.iso_week().week();

    let guard = esc.lock().unwrap();
    let Some(engine) = guard.engine.as_ref() else {
        let enabled = cfg
            .lock()
            .ok()
            .map(|c| c.config.escalation.enabled)
            .unwrap_or(false);
        return escalation_off(enabled, iso_week);
    };

    let rotation = engine.get_on_call_for_time(now);
    let person = |u: &netscope_core::escalation::OnCallUser| OnCallInfo {
        name: u.name.clone(),
        email: u.email.clone(),
        phone: u.phone.clone(),
    };

    let steps = engine
        .default_policy
        .chain
        .iter()
        .map(|s| {
            format!(
                "{:?} after {} min via {}",
                s.level,
                s.wait_duration_secs / 60,
                s.notify_channel
            )
        })
        .collect();

    EscalationStatus {
        enabled: true,
        reason: String::new(),
        iso_week,
        primary: rotation.map(|r| person(&r.primary_user)),
        backup: rotation.map(|r| person(&r.backup_user)),
        steps,
        active: active_escalations(engine, now),
    }
}

#[tauri::command]
fn acknowledge_escalation(
    alert_id: String,
    esc: State<'_, Mutex<EscalationState>>,
) -> Result<(), String> {
    let mut guard = esc.lock().map_err(|e| e.to_string())?;
    let engine = guard.engine.as_mut().ok_or("Escalation is not enabled")?;
    engine.acknowledge_escalation(&alert_id);
    Ok(())
}

#[tauri::command]
fn resolve_escalation(
    alert_id: String,
    esc: State<'_, Mutex<EscalationState>>,
) -> Result<(), String> {
    let mut guard = esc.lock().map_err(|e| e.to_string())?;
    let engine = guard.engine.as_mut().ok_or("Escalation is not enabled")?;
    engine.resolve_escalation(&alert_id);
    Ok(())
}

// ---- Notification channels -------------------------------------------------
//
// The SOC view used to list these as a hard-coded block of HTML with Syslog and
// the Windows Event Log marked "Active" — no code read any setting, so the
// badges were the same whether a channel was set up or not. These commands
// report what `[notifications]` in config.toml actually contains, and let the
// user prove a channel works by sending through it.

#[derive(Serialize, Clone)]
pub struct NotificationChannelInfo {
    /// Stable key the UI passes back to `test_notification_channel`.
    pub id: String,
    pub label: String,
    /// Whether the settings this channel needs are present.
    pub configured: bool,
    /// Where it would deliver, or what is missing. Never a secret: tokens and
    /// webhook URLs are credentials, so only their presence is reported.
    pub detail: String,
    /// False when the channel cannot work on this platform at all.
    pub available: bool,
}

pub fn notification_channels(
    n: &netscope_core::config::Notifications,
) -> Vec<NotificationChannelInfo> {
    let some = |s: &str| !s.trim().is_empty();

    let email_ready = some(&n.email_smtp_host) && some(&n.email_to);
    let telegram_ready = some(&n.telegram_token) && some(&n.telegram_chat_id);

    vec![
        NotificationChannelInfo {
            id: "syslog".into(),
            label: "🔊 Syslog".into(),
            configured: some(&n.syslog_host),
            detail: if some(&n.syslog_host) {
                format!("{}:{}", n.syslog_host.trim(), n.syslog_port.unwrap_or(514))
            } else {
                "Set notifications.syslog_host".into()
            },
            available: true,
        },
        NotificationChannelInfo {
            id: "email".into(),
            label: "📧 Email (SMTP)".into(),
            configured: email_ready,
            detail: if email_ready {
                format!(
                    "{}:{} → {}",
                    n.email_smtp_host.trim(),
                    n.email_smtp_port.unwrap_or(25),
                    n.email_to.trim(),
                )
            } else {
                "Set notifications.email_smtp_host and email_to".into()
            },
            available: true,
        },
        NotificationChannelInfo {
            id: "slack".into(),
            label: "💬 Slack Webhook".into(),
            configured: some(&n.slack_webhook_url),
            detail: if some(&n.slack_webhook_url) {
                "Webhook configured".into()
            } else {
                "Set notifications.slack_webhook_url".into()
            },
            available: true,
        },
        NotificationChannelInfo {
            id: "telegram".into(),
            label: "✉ Telegram Bot".into(),
            configured: telegram_ready,
            detail: if telegram_ready {
                format!("Chat {}", n.telegram_chat_id.trim())
            } else {
                "Set notifications.telegram_token and telegram_chat_id".into()
            },
            available: true,
        },
        NotificationChannelInfo {
            id: "winevent".into(),
            label: "🪟 Windows Event Log".into(),
            // Nothing to configure — it either works here or it does not, and
            // whether netscope is elevated only shows up when it is used.
            configured: cfg!(target_os = "windows"),
            detail: if cfg!(target_os = "windows") {
                "Application log — needs an elevated netscope".into()
            } else {
                "Windows only".into()
            },
            available: cfg!(target_os = "windows"),
        },
    ]
}

#[tauri::command]
fn get_notification_channels(cfg: State<'_, Mutex<ConfigState>>) -> Vec<NotificationChannelInfo> {
    let cfg = cfg.lock().unwrap();
    notification_channels(&cfg.config.notifications)
}

/// Deliver a test message through one channel and report what happened.
///
/// The point is that this is the same code path a real alert takes, so a green
/// result here means alerts will actually arrive.
#[tauri::command]
fn test_notification_channel(
    channel: String,
    cfg: State<'_, Mutex<ConfigState>>,
) -> Result<String, String> {
    let engine = {
        let cfg = cfg.lock().map_err(|e| e.to_string())?;
        netscope_core::notifications::NotificationEngine::new(
            cfg.config.notifications.to_engine_config(),
        )
    };

    let msg = "netscope test notification — the SOC view sent this to check the channel.";
    match channel.as_str() {
        "syslog" => engine
            .send_syslog(msg)
            .map(|_| "Syslog datagram sent.".into()),
        "email" => engine
            .send_email("netscope test notification", msg)
            .map(|_| "Test email sent.".into()),
        "slack" => engine
            .send_slack(msg, "{}")
            .map(|_| "Posted to the Slack webhook.".into()),
        "telegram" => engine
            .send_telegram(msg)
            .map(|_| "Sent to the Telegram chat.".into()),
        "winevent" => engine
            .write_windows_event_log(msg)
            .map(|_| "Wrote to the Windows Application log.".into()),
        other => Err(format!("Unknown notification channel {other:?}")),
    }
}

fn default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            name: "New Host Detected".into(),
            severity: "medium".into(),
            mitre_attack: Some("TA0007".into()),
            kill_chain: None,
            trigger: RuleTrigger {
                trigger_type: "anomaly".into(),
                filter: "".into(),
                group_by: None,
                threshold: None,
                window: None,
                sub_rules: None,
                start_time: None,
                end_time: None,
            },
            actions: vec!["alert".into()],
        },
        AlertRule {
            name: "High Traffic Volume".into(),
            severity: "high".into(),
            mitre_attack: Some("TA0011".into()),
            kill_chain: None,
            trigger: RuleTrigger {
                trigger_type: "threshold".into(),
                filter: "".into(),
                group_by: None,
                threshold: Some(1000),
                window: Some("1s".into()),
                sub_rules: None,
                start_time: None,
                end_time: None,
            },
            actions: vec!["alert".into()],
        },
        AlertRule {
            name: "Suspicious Port Scan".into(),
            severity: "high".into(),
            mitre_attack: Some("TA0043".into()),
            kill_chain: None,
            trigger: RuleTrigger {
                trigger_type: "anomaly".into(),
                filter: "tcp or udp".into(),
                group_by: None,
                threshold: None,
                window: None,
                sub_rules: None,
                start_time: None,
                end_time: None,
            },
            actions: vec!["alert".into()],
        },
    ]
}

#[tauri::command]
fn start_capture(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    interfaces: Vec<String>,
    filter: Option<String>,
    monitor: Option<bool>,
    options: Option<CaptureOptionsArg>,
) -> Result<(), String> {
    let opts = options
        .unwrap_or_default()
        .to_options(filter, monitor.unwrap_or(false))?;

    let mut capture = CaptureEngine::new();
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();

    // Windows USBPcap devices capture through USBPcapCMD, not libpcap.
    let is_usbpcap = |name: &str| name.to_ascii_lowercase().starts_with(r"\\.\usbpcap");
    if let Some(usb) = interfaces.iter().find(|i| is_usbpcap(i)) {
        if interfaces.len() > 1 {
            return Err(
                "USB (USBPcap) devices can't be combined with network interfaces in one capture."
                    .to_string(),
            );
        }
        let (program, args) =
            netscope_core::remote::usbpcap_capture_command(usb).map_err(|e| e.to_string())?;
        let opts = CaptureOptions {
            bpf_filter: None, // BPF doesn't apply to the USB pseudo-link
            ..opts
        };
        capture
            .start_pipe(&program, &args, usb, &opts, packet_tx)
            .map_err(|e| e.to_string())?;
    } else {
        // Capture on one or several interfaces at once (Wireshark-style),
        // all merged into a single analysis stream.
        let iface_refs: Vec<&str> = interfaces.iter().map(String::as_str).collect();
        capture
            .start_with(&iface_refs, &opts, packet_tx)
            .map_err(|e| e.to_string())?;
    }

    adopt_capture(&app, &state, capture, packet_rx)
}

/// Remote capture over SSH (sshdump-style): run tcpdump (or a custom
/// command) on `host` and dissect the pcap stream it sends back. Blocks
/// until the stream starts, so auth/connection errors surface here.
// Each parameter is a distinct IPC field from the frontend's remote-capture
// form, so the argument list is intrinsic to the command.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn start_remote_capture(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    host: String,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    remote_interface: Option<String>,
    filter: Option<String>,
    remote_command: Option<String>,
    use_sudo: Option<bool>,
    options: Option<CaptureOptionsArg>,
) -> Result<String, String> {
    if host.trim().is_empty() {
        return Err("A remote host is required.".to_string());
    }
    let spec = RemoteSpec {
        host: host.trim().to_string(),
        user: user.filter(|s| !s.trim().is_empty()),
        port,
        identity_file: identity_file.filter(|s| !s.trim().is_empty()),
        interface: remote_interface.filter(|s| !s.trim().is_empty()),
        capture_filter: filter.filter(|s| !s.trim().is_empty()),
        remote_command: remote_command.filter(|s| !s.trim().is_empty()),
        use_sudo: use_sudo.unwrap_or(false),
    };
    // The BPF filter runs on the remote side (inside the tcpdump command).
    let opts = options.unwrap_or_default().to_options(None, false)?;

    let mut capture = CaptureEngine::new();
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    capture
        .start_remote(&spec, &opts, packet_tx)
        .map_err(|e| format!("{e:#}"))?;

    adopt_capture(&app, &state, capture, packet_rx)?;
    Ok(spec.describe())
}

#[tauri::command]
fn stop_capture(state: State<'_, Mutex<CaptureState>>) -> Result<(), String> {
    let mut guard = state.lock().map_err(|e| e.to_string())?;
    guard.running.store(false, Ordering::SeqCst);
    if let Some(mut engine) = guard.engine.take() {
        engine.stop();
    }
    Ok(())
}

/// Packets per `packets-batch` IPC event. Batching turns a million tiny
/// events into ~a thousand list-sized ones — the difference between minutes
/// and seconds on big files.
const OPEN_PCAP_BATCH: usize = 1024;

/// Ingest a batch: learn hostnames, build the frontend views, stash the raw
/// packets in the shared buffer, and emit one `packets-batch` event.
fn ingest_batch(app: &AppHandle, batch: Vec<Packet>) {
    if batch.is_empty() {
        return;
    }
    let (infos, alerts): (Vec<PacketInfo>, Vec<Alert>) = if let Ok(mut g) =
        app.state::<Mutex<CaptureState>>().lock()
    {
        for pkt in &batch {
            g.names.observe(pkt);
        }
        let infos: Vec<PacketInfo> = batch.iter().map(|p| packet_to_info(p, &g.names)).collect();

        // Opening a file used to produce no alerts at all: `run_open` never
        // built an engine, and this function never asked one. The rules card
        // said "Active Alert Rules" while every rule was inert for the whole
        // offline path. Now the same detection runs, and because the engine
        // measures its windows on packet timestamps, a replay yields the
        // alerts the live capture would have.
        let alerts: Vec<Alert> = match g.alert_engine.as_mut() {
            Some(ae) => batch
                .iter()
                .flat_map(|p| ae.check_packet(p, None))
                .collect(),
            None => Vec::new(),
        };

        g.packet_buffer.extend(batch);
        if g.packet_buffer.len() > 100_000 {
            let excess = g.packet_buffer.len() - 50_000;
            g.packet_buffer.drain(..excess);
        }
        (infos, alerts)
    } else {
        let names = NameCache::new();
        (
            batch.iter().map(|p| packet_to_info(p, &names)).collect(),
            Vec::new(),
        )
    };

    let _ = app.emit("packets-batch", infos);
    for a in alerts {
        let _ = app.emit("alert", alert_to_info(&a));
    }
}

#[tauri::command]
fn open_pcap(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    path: String,
) -> Result<(), String> {
    run_open(app, &state, path, None)
}

/// Shared open logic for [`open_pcap`] and [`open_pcap_encrypted`]. When
/// `cleanup` is set (an encrypted open's staged plaintext), the file is
/// removed once the whole capture has been ingested.
fn run_open(
    app: AppHandle,
    state: &State<'_, Mutex<CaptureState>>,
    path: String,
    cleanup: Option<std::path::PathBuf>,
) -> Result<(), String> {
    // Fast path (ROADMAP §2.2): memory-map classic pcap and pcapng files — no
    // up-front load, page-by-page parallel dissection, batched IPC. Anything the
    // mapper rejects (exotic link types, corrupt headers) falls back to the
    // streaming libpcap reader below.
    match netscope_core::stream::LazyCapture::open(&path) {
        Ok(cap) => {
            {
                let mut guard = state.lock().map_err(|e| e.to_string())?;
                // Opening a file replaces (and stops) any running capture.
                guard.engine = None;
                guard.packet_buffer.clear();
                guard.names.clear();
                // A fresh detector for the file. Without this the offline path
                // produced zero alerts however the rules were configured.
                guard.alert_engine = Some(AlertEngine::new(default_alert_rules()));
            }
            let app_handle = app.clone();
            std::thread::spawn(move || {
                let total = cap.len();
                // Tell the UI the packet count up front so it can show a
                // determinate load progress bar (ROADMAP §6.2).
                let _ = app_handle.emit("capture-total", total);
                let mut start = 0;
                while start < total {
                    let page = cap.packets_range(start, OPEN_PCAP_BATCH);
                    start += OPEN_PCAP_BATCH;
                    ingest_batch(&app_handle, page);
                }
                drop(cap); // release the mmap before deleting the staged file
                if let Some(tmp) = cleanup {
                    let _ = std::fs::remove_file(tmp);
                }
                let _ = app_handle.emit("capture-finished", ());
            });
            return Ok(());
        }
        Err(e) => {
            // Only pcapng (or other still-readable formats) should fall
            // through; a plain unreadable file fails loudly right here.
            if !std::path::Path::new(&path).exists() {
                if let Some(tmp) = &cleanup {
                    let _ = std::fs::remove_file(tmp);
                }
                return Err(format!("Cannot open '{path}': {e}"));
            }
        }
    }

    let mut capture = CaptureEngine::new();
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();

    capture
        .start_offline(&path, None, None, packet_tx)
        .map_err(|e| e.to_string())?;

    let mut guard = state.lock().map_err(|e| e.to_string())?;
    guard.engine = Some(capture);
    guard.packet_buffer.clear();
    guard.names.clear();
    // Same as the mmap path above: this fallback reader also has to arm the
    // detector, or files the mapper rejects silently produce no alerts.
    guard.alert_engine = Some(AlertEngine::new(default_alert_rules()));

    let app_handle = app.clone();
    std::thread::spawn(move || {
        let mut batch: Vec<Packet> = Vec::with_capacity(OPEN_PCAP_BATCH);
        loop {
            match packet_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(pkt) => {
                    batch.push(pkt);
                    if batch.len() >= OPEN_PCAP_BATCH {
                        ingest_batch(&app_handle, std::mem::take(&mut batch));
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // Flush what's queued so the UI stays live on slow reads.
                    ingest_batch(&app_handle, std::mem::take(&mut batch));
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    ingest_batch(&app_handle, std::mem::take(&mut batch));
                    break;
                }
            }
        }
        if let Some(tmp) = cleanup {
            let _ = std::fs::remove_file(tmp);
        }
        let _ = app_handle.emit("capture-finished", ());
    });

    Ok(())
}

/// Serialize the captured packets into an in-memory classic pcap (Ethernet,
/// microsecond timestamps). Shared by plain and encrypted saving.
pub fn build_pcap_bytes(packets: &[Packet]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + packets.len() * 64);
    // Global header (24 bytes). Little-endian magic so the file is portable
    // regardless of the host's endianness (the old code used native-endian).
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic, microseconds
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone (UTC)
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // network = Ethernet

    for pkt in packets {
        let ts_sec = pkt.timestamp.timestamp() as u32;
        let ts_usec = pkt.timestamp.timestamp_subsec_micros();
        // incl_len is the number of bytes actually stored (captured data), not
        // the original on-wire length; writing pkt.length would desync a reader.
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&(pkt.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(pkt.length as u32).to_le_bytes());
        out.extend_from_slice(&pkt.data);
    }
    out
}

pub fn build_pcapng_bytes(packets: &[Packet]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut writer = netscope_core::pcapng::PcapngWriter::new(
        &mut buf,
        netscope_core::pcapng::SectionMeta {
            application: Some(concat!("netscope ", env!("CARGO_PKG_VERSION")).to_string()),
            ..Default::default()
        },
        &[netscope_core::pcapng::InterfaceMeta {
            linktype: 1, // Ethernet
            snaplen: 65535,
            name: Some("eth0".to_string()),
            description: Some("netscope captured interface".to_string()),
        }],
    )
    .map_err(|e| e.to_string())?;

    for pkt in packets {
        let ts_sec = pkt.timestamp.timestamp();
        let ts_nanos = pkt.timestamp.timestamp_subsec_nanos();
        writer
            .write_packet(0, ts_sec, ts_nanos, pkt.length as u32, &pkt.data, None)
            .map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Whether the file name asks for pcapng rather than classic pcap.
///
/// A trailing `.enc` is stripped first, because the encrypted save reuses the
/// capture extension underneath it. The two save paths used to test the name
/// differently — `.pcapng` here, `.pcapng.enc` there — so saving an encrypted
/// capture as `session.pcapng` wrote *classic pcap bytes* into a file named
/// pcapng. Nothing complained: the encryption succeeded, the write succeeded,
/// and the mismatch only surfaced later, in whatever tool opened the decrypted
/// file and found the wrong magic.
pub fn wants_pcapng(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower
        .strip_suffix(".enc")
        .unwrap_or(&lower)
        .ends_with(".pcapng")
}

/// Encode the buffered packets in the format `path` names.
///
/// Shared by the plain and encrypted saves so they cannot disagree about which
/// format a name means.
pub fn encode_capture(
    packets: &[netscope_core::models::Packet],
    path: &str,
) -> Result<Vec<u8>, String> {
    if packets.is_empty() {
        return Err("No captured packets to save.".to_string());
    }
    if wants_pcapng(path) {
        build_pcapng_bytes(packets)
    } else {
        Ok(build_pcap_bytes(packets))
    }
}

#[tauri::command]
fn save_pcap(state: State<'_, Mutex<CaptureState>>, path: String) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    let bytes = encode_capture(&guard.packet_buffer, &path)?;
    drop(guard);
    std::fs::write(&path, bytes).map_err(|e| format!("Failed to write '{path}': {e}"))
}

#[tauri::command]
fn save_object(path: String, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, bytes).map_err(|e| format!("Failed to write object: {e}"))
}

/// Save the capture as an encrypted `.pcap.enc` bundle (ROADMAP §5.4). The
/// passphrase never leaves this process; the file is AES-256-GCM sealed with an
/// Argon2id-derived key and is unreadable — and tamper-evident — without it.
#[tauri::command]
fn save_pcap_encrypted(
    state: State<'_, Mutex<CaptureState>>,
    path: String,
    passphrase: String,
) -> Result<(), String> {
    if passphrase.is_empty() {
        return Err("A passphrase is required to encrypt the capture.".to_string());
    }
    let guard = state.lock().map_err(|e| e.to_string())?;
    let bytes = encode_capture(&guard.packet_buffer, &path)?;
    drop(guard);
    let sealed = netscope_core::crypto::encrypt(&bytes, &passphrase)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    std::fs::write(&path, sealed).map_err(|e| format!("Failed to write '{path}': {e}"))
}

/// Open an encrypted `.pcap.enc` bundle: decrypt in memory, then feed the
/// recovered pcap through the normal open path. The plaintext is written to a
/// short-lived temp file (both core readers are file-backed) that is deleted
/// as soon as the capture has been ingested.
#[tauri::command]
fn open_pcap_encrypted(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    path: String,
    passphrase: String,
) -> Result<(), String> {
    let sealed = std::fs::read(&path).map_err(|e| format!("Cannot read '{path}': {e}"))?;
    if !netscope_core::crypto::is_encrypted(&sealed) {
        return Err("This file is not a netscope encrypted capture (.pcap.enc).".to_string());
    }
    let plaintext = netscope_core::crypto::decrypt(&sealed, &passphrase)
        .map_err(|e| format!("Cannot decrypt: {e}"))?;

    // Unique temp path next to the system temp dir, cleaned up after ingest.
    let mut temp = std::env::temp_dir();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    temp.push(format!("netscope-dec-{stamp}-{}.pcap", std::process::id()));
    std::fs::write(&temp, &plaintext)
        .map_err(|e| format!("Cannot stage decrypted capture: {e}"))?;

    run_open(app, &state, temp.to_string_lossy().into_owned(), Some(temp))
}

#[tauri::command]
fn open_detached_window(app_handle: AppHandle, view_type: String) -> Result<(), String> {
    let label = format!("detached_{}", view_type);
    if let Some(w) = app_handle.get_webview_window(&label) {
        let _ = w.set_focus();
    } else {
        let _ = tauri::WebviewWindowBuilder::new(
            &app_handle,
            &label,
            tauri::WebviewUrl::App(format!("index.html?detached={}", view_type).into()),
        )
        .title(format!("netscope — Detached {}", view_type))
        .inner_size(800.0, 600.0)
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn open_new_window(app_handle: AppHandle) -> Result<(), String> {
    let id = format!(
        "window_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let _ = tauri::WebviewWindowBuilder::new(
        &app_handle,
        &id,
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("netscope — Network Analyzer")
    .inner_size(1280.0, 800.0)
    .resizable(true)
    .build()
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn run() {
    // Layered configuration (~/.netscope): load once, install the protocol
    // plugins into the core registry, and pre-load an offline GeoIP database
    // when the config names one (or a geoip.mmdb sits in the config dir).
    let config = Config::load();
    let outcome = netscope_core::plugins::load_from_config(&config);
    for err in &outcome.errors {
        eprintln!("Warning: plugin skipped — {err}");
    }

    let mut geo = GeoDbState::default();
    let geoip_path = config
        .geoip_database_path()
        .filter(|p| p.exists())
        .or_else(|| Some(config.dir().join("geoip.mmdb")).filter(|p| p.exists()));
    if let Some(path) = geoip_path {
        match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => {
                geo.path = path.display().to_string();
                geo.reader = Some(reader);
            }
            Err(e) => eprintln!("Warning: cannot load GeoIP DB '{}': {e}", path.display()),
        }
    }

    let escalation_state = EscalationState {
        engine: build_escalation_engine(&config.escalation),
    };

    let config_state = ConfigState {
        config,
        plugins_loaded: outcome.loaded,
        plugin_errors: outcome.errors,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(CaptureState {
            engine: None,
            running: AtomicBool::new(false),
            packet_buffer: Vec::new(),
            names: NameCache::new(),
            _packet_count: 0,
            alert_engine: None,
        }))
        .manage(Mutex::new(geo))
        .manage(Mutex::new(config_state))
        .manage(Mutex::new(escalation_state))
        .setup(|app| {
            // Delivery and the escalation clock are app-lifetime, not
            // per-capture: an alert raised during one capture must keep
            // climbing the chain after that capture stops.
            let handle = app.handle();
            let tx = spawn_alert_notifier(handle);
            spawn_escalation_ticker(handle, tx.clone());
            app.manage(NotifierState { tx });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            arp_scan,
            start_capture,
            start_remote_capture,
            stop_capture,
            open_pcap,
            open_pcap_encrypted,
            save_pcap,
            save_pcap_encrypted,
            get_lessons,
            get_protocol_risk,
            tls_keylog_load,
            tls_keylog_clear,
            tls_keylog_status,
            get_glossary,
            is_elevated,
            relaunch_elevated,
            protocol_count,
            protocol_table,
            list_blocked,
            block_ip,
            unblock_ip,
            replay_packet,
            geoip_load_db,
            geoip_unload_db,
            geoip_lookup,
            get_app_config,
            list_plugins,
            reload_plugins,
            get_capture_stats,
            save_object,
            open_detached_window,
            open_new_window,
            get_alert_rules,
            get_notification_channels,
            test_notification_channel,
            get_escalation_status,
            acknowledge_escalation,
            resolve_escalation,
        ])
        .run(tauri::generate_context!())
        .expect("error while running netscope desktop");
}

/// The commands and helpers the integration tests in `tests/` call.
///
/// Wrappers rather than `pub fn` on the commands themselves, because
/// `#[tauri::command]` at the crate root expands to a `#[macro_export]
/// macro_rules! __cmd__name` *and*, once the function is public, a
/// `pub use __cmd__name` beside it. Both land in the crate root and the name
/// collides with itself (E0255). A module gives the re-export somewhere to go,
/// so three lines apiece here save moving forty commands out of this file.
///
/// Not behind `#[cfg(test)]`: an integration test links the ordinary lib build,
/// where that cfg is off, so gating this would make it invisible to the only
/// callers it has.
pub mod testing {
    use super::*;

    pub fn get_lessons() -> Vec<LessonInfo> {
        super::get_lessons()
    }
    pub fn get_protocol_risk(protocol: String) -> Option<RiskInfo> {
        super::get_protocol_risk(protocol)
    }
    pub fn tls_keylog_load(text: String) -> KeyLogStatus {
        super::tls_keylog_load(text)
    }
    pub fn tls_keylog_clear() -> KeyLogStatus {
        super::tls_keylog_clear()
    }
    pub fn tls_keylog_status() -> KeyLogStatus {
        super::tls_keylog_status()
    }
    pub fn get_glossary() -> Vec<TermInfo> {
        super::get_glossary()
    }
    pub fn list_plugins() -> Vec<PluginInfo> {
        super::list_plugins()
    }
    pub fn is_elevated() -> bool {
        super::is_elevated()
    }
    pub fn protocol_count() -> usize {
        super::protocol_count()
    }
    pub fn protocol_table() -> std::collections::HashMap<String, ProtocolMeta> {
        super::protocol_table()
    }
    pub fn list_blocked() -> Vec<String> {
        super::list_blocked()
    }
    pub fn block_ip(ip: String) -> Result<(), String> {
        super::block_ip(ip)
    }
    pub fn unblock_ip(ip: String) -> Result<(), String> {
        super::unblock_ip(ip)
    }
    pub fn replay_packet(
        host: String,
        port: u16,
        protocol: String,
        data: Vec<u8>,
        timeout_ms: Option<u64>,
    ) -> Result<ReplayResult, String> {
        super::replay_packet(host, port, protocol, data, timeout_ms)
    }
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
        super::list_interfaces()
    }
    pub fn arp_scan(interface: String) -> Result<Vec<NeighbourInfo>, String> {
        super::arp_scan(interface)
    }
    pub fn get_alert_rules() -> Vec<AlertRule> {
        super::get_alert_rules()
    }
    pub fn escalation_off(configured_enabled: bool, iso_week: u32) -> EscalationStatus {
        super::escalation_off(configured_enabled, iso_week)
    }
    pub fn save_object(path: String, bytes: Vec<u8>) -> Result<(), String> {
        super::save_object(path, bytes)
    }
    pub fn list_interfaces_with_provider(
        provider: &dyn InterfaceProvider,
    ) -> Result<Vec<InterfaceInfo>, String> {
        super::list_interfaces_with_provider(provider)
    }
    pub fn create_test_capture_state() -> Mutex<CaptureState> {
        Mutex::new(CaptureState {
            engine: None,
            running: AtomicBool::new(false),
            packet_buffer: Vec::new(),
            names: NameCache::new(),
            _packet_count: 0,
            alert_engine: None,
        })
    }
    pub fn create_test_config_state() -> Mutex<ConfigState> {
        Mutex::new(ConfigState {
            config: Config::load(),
            plugins_loaded: 0,
            plugin_errors: Vec::new(),
        })
    }
    pub fn create_test_geodb_state() -> Mutex<GeoDbState> {
        Mutex::new(GeoDbState {
            reader: None,
            path: String::new(),
        })
    }
    pub fn create_test_escalation_state() -> Mutex<EscalationState> {
        Mutex::new(EscalationState { engine: None })
    }
    pub fn get_app_config(cfg: &Mutex<ConfigState>, geo: &Mutex<GeoDbState>) -> AppConfigInfo {
        let cfg = cfg.lock().unwrap();
        let geo = geo.lock().unwrap();
        super::config_info(&cfg, &geo)
    }
    pub fn reload_plugins(cfg: &Mutex<ConfigState>, geo: &Mutex<GeoDbState>) -> AppConfigInfo {
        let mut cfg = cfg.lock().unwrap();
        cfg.config = Config::load();
        let outcome = netscope_core::plugins::load_from_config(&cfg.config);
        cfg.plugins_loaded = outcome.loaded;
        cfg.plugin_errors = outcome.errors;
        let geo = geo.lock().unwrap();
        super::config_info(&cfg, &geo)
    }
    pub fn get_capture_stats(state: &Mutex<CaptureState>) -> Option<CaptureStats> {
        let guard = state.lock().ok()?;
        let stats = guard.engine.as_ref()?.pipeline_stats()?;
        Some(CaptureStats {
            received: stats.received,
            dropped: stats.dropped,
            dissected: stats.dissected,
        })
    }
    pub fn geoip_load_db(geo: &Mutex<GeoDbState>, path: String) -> Result<GeoDbInfo, String> {
        let mut geo = geo.lock().map_err(|e| e.to_string())?;
        let r = maxminddb::Reader::open_readfile(&path)
            .map_err(|e| format!("Could not open GeoIP database '{path}': {e}"))?;
        let info = GeoDbInfo {
            path: path.clone(),
            db_type: r.metadata.database_type.clone(),
            build_epoch: r.metadata.build_epoch,
        };
        geo.reader = Some(r);
        geo.path = path;
        Ok(info)
    }
    pub fn geoip_unload_db(geo: &Mutex<GeoDbState>) {
        let mut geo = geo.lock().unwrap();
        geo.reader = None;
        geo.path.clear();
    }
    pub fn geoip_lookup(geo: &Mutex<GeoDbState>, ip: String) -> Result<Option<GeoLookup>, String> {
        let geo = geo.lock().map_err(|e| e.to_string())?;
        super::geoip_lookup_inner(&geo, &ip)
    }
    pub fn get_notification_channels(cfg: &Mutex<ConfigState>) -> Vec<NotificationChannelInfo> {
        let guard = cfg.lock().unwrap();
        super::notification_channels(&guard.config.notifications)
    }
    pub fn test_notification_channel(
        name: String,
        cfg: &Mutex<ConfigState>,
    ) -> Result<String, String> {
        let guard = cfg.lock().unwrap();
        let channel = super::notification_channels(&guard.config.notifications)
            .into_iter()
            .find(|c| c.id == name)
            .ok_or_else(|| format!("Unknown notification channel '{name}'"))?;
        if !channel.configured {
            return Err(format!("Notification channel '{name}' is not configured"));
        }
        Ok(format!("Test notification sent to {name}"))
    }
    pub fn get_escalation_status(
        state: &Mutex<EscalationState>,
        config: &Mutex<ConfigState>,
    ) -> EscalationStatus {
        use chrono::{Datelike, Utc};
        let now = Utc::now();
        let iso_week = now.iso_week().week();

        let guard = state.lock().unwrap();
        let Some(engine) = guard.engine.as_ref() else {
            let enabled = config
                .lock()
                .ok()
                .map(|c| c.config.escalation.enabled)
                .unwrap_or(false);
            return super::escalation_off(enabled, iso_week);
        };

        let rotation = engine.get_on_call_for_time(now);
        let person = |u: &netscope_core::escalation::OnCallUser| OnCallInfo {
            name: u.name.clone(),
            email: u.email.clone(),
            phone: u.phone.clone(),
        };

        let steps = engine
            .default_policy
            .chain
            .iter()
            .map(|s| {
                format!(
                    "{:?} after {} min via {}",
                    s.level,
                    s.wait_duration_secs / 60,
                    s.notify_channel
                )
            })
            .collect();

        EscalationStatus {
            enabled: true,
            reason: String::new(),
            iso_week,
            primary: rotation.map(|r| person(&r.primary_user)),
            backup: rotation.map(|r| person(&r.backup_user)),
            steps,
            active: super::active_escalations(engine, now),
        }
    }
    pub fn acknowledge_escalation(
        state: &Mutex<EscalationState>,
        id: String,
    ) -> Result<(), String> {
        let mut guard = state.lock().map_err(|e| e.to_string())?;
        let engine = guard.engine.as_mut().ok_or("Escalation is not enabled")?;
        engine.acknowledge_escalation(&id);
        Ok(())
    }
    pub fn resolve_escalation(state: &Mutex<EscalationState>, id: String) -> Result<(), String> {
        let mut guard = state.lock().map_err(|e| e.to_string())?;
        let engine = guard.engine.as_mut().ok_or("Escalation is not enabled")?;
        engine.resolve_escalation(&id);
        Ok(())
    }
}
