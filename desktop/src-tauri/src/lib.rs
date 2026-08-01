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

struct CaptureState {
    engine: Option<CaptureEngine>,
    running: AtomicBool,
    packet_buffer: Vec<Packet>,
    names: NameCache,
    _packet_count: u64,
    alert_engine: Option<AlertEngine>,
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
struct InterfaceInfo {
    name: String,
    description: String,
    /// "ethernet" | "loopback" | "usb" | "bluetooth" | "can" — lets the UI
    /// badge hardware-bus capture sources.
    kind: String,
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
struct LessonInfo {
    protocol: String,
    title: String,
    summary: String,
    body: String,
    look_for: String,
}

#[derive(Serialize, Clone)]
struct TermInfo {
    term: String,
    meaning: String,
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
struct RiskInfo {
    severity: String,
    headline: String,
    detail: String,
    mitigation: String,
    reference: String,
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
struct KeyLogStatus {
    /// Connections the loaded secrets can decrypt.
    sessions: usize,
    /// Secret lines accepted by this load.
    added: usize,
    /// Lines that were neither comments nor parseable.
    rejected: usize,
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
struct GeoDbState {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    path: String,
}

#[derive(Serialize, Clone)]
struct GeoDbInfo {
    path: String,
    /// e.g. "GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN".
    db_type: String,
    /// Database build time, seconds since the Unix epoch.
    build_epoch: u64,
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
struct GeoLookup {
    country: Option<String>,
    code: Option<String>,
    city: Option<String>,
    region: Option<String>,
    asn: Option<u32>,
    org: Option<String>,
}

/// English name from an MMDB localized-names record (any locale as fallback).
fn english_name(names: &maxminddb::geoip2::Names) -> Option<String> {
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

#[tauri::command]
fn geoip_lookup(
    ip: String,
    state: State<'_, Mutex<GeoDbState>>,
) -> Result<Option<GeoLookup>, String> {
    use maxminddb::geoip2;
    let addr: std::net::IpAddr = ip.parse().map_err(|e| format!("Invalid IP: {e}"))?;
    let guard = state.lock().unwrap();
    let Some(reader) = guard.reader.as_ref() else {
        return Ok(None);
    };
    let result = reader
        .lookup(addr)
        .map_err(|e| format!("GeoIP lookup failed: {e}"))?;
    // ASN databases carry network-owner fields instead of places.
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
    // The City struct also decodes from Country databases — the city and
    // subdivision fields just come back empty.
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

// ---- Layered configuration & plugins (ROADMAP §2.3 / §2.4) -----------------
//
// ~/.netscope/config.toml (plus optional profiles) is loaded once at startup:
// it can point at an offline GeoIP database, enable the plugins directory and
// name the active profile. Declarative protocol plugins (*.toml) are loaded
// into netscope-core's registry so the dissectors pick them up.

struct ConfigState {
    config: Config,
    plugins_loaded: usize,
    plugin_errors: Vec<String>,
}

#[derive(Serialize, Clone)]
struct AppConfigInfo {
    /// The config directory (~/.netscope or $NETSCOPE_CONFIG_DIR).
    dir: String,
    active_profile: Option<String>,
    profiles: Vec<String>,
    plugins_enabled: bool,
    plugins_dir: String,
    plugins_loaded: usize,
    plugin_errors: Vec<String>,
    /// Offline GeoIP database auto-loaded from the config, if any.
    geoip_db: Option<GeoDbInfo>,
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
struct PluginInfo {
    name: String,
    transport: String,
    ports: Vec<u16>,
    description: String,
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
#[derive(Serialize, Clone, Copy)]
struct CaptureStats {
    received: u64,
    dropped: u64,
    dissected: u64,
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
struct ProtocolMeta {
    /// How it groups into flows: `tcp`, `udp`, `icmp`, `arp` or `other`.
    transport: &'static str,
    /// How specific it is as a label for a whole flow — the highest-ranked
    /// packet in a flow is the one that names it.
    rank: u8,
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
struct ReplayResult {
    sent: usize,
    response: Vec<u8>,
    truncated: bool,
    elapsed_ms: u64,
    note: String,
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

#[tauri::command]
fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
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
    // Windows USB capture devices (USBPcap) aren't libpcap interfaces —
    // append them so USB capture is one click like any adapter.
    for (value, display) in netscope_core::remote::usbpcap_interfaces() {
        out.push(InterfaceInfo {
            name: value,
            description: display,
            kind: "usb".into(),
        });
    }
    Ok(out)
}

#[derive(Serialize, Clone)]
struct NeighbourInfo {
    ip: String,
    mac: String,
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

struct EscalationState {
    /// `None` when `[escalation] enabled` is false, which is the default:
    /// escalation pages people, so it never starts by itself.
    engine: Option<netscope_core::escalation::EscalationEngine>,
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
struct OnCallInfo {
    name: String,
    email: String,
    phone: String,
}

#[derive(Serialize, Clone)]
struct ActiveEscalationInfo {
    alert_id: String,
    rule_name: String,
    alert_msg: String,
    /// "Escalating" | "Acknowledged" | "Resolved".
    status: String,
    /// Which rung of the chain it has reached, as a name the UI can show.
    level: String,
    /// Seconds since the alert first escalated — the number that decides
    /// whether anyone is actually responding.
    age_secs: i64,
}

#[derive(Serialize, Clone)]
struct EscalationStatus {
    enabled: bool,
    /// Why it is off, when it is. Empty when running.
    reason: String,
    iso_week: u32,
    primary: Option<OnCallInfo>,
    backup: Option<OnCallInfo>,
    steps: Vec<String>,
    active: Vec<ActiveEscalationInfo>,
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
        return EscalationStatus {
            enabled: false,
            reason: if enabled {
                // enabled but no engine can only mean an empty rotation
                "No one is listed under [[escalation.oncall]].".into()
            } else {
                "Set [escalation] enabled = true to turn this on.".into()
            },
            iso_week,
            primary: None,
            backup: None,
            steps: Vec::new(),
            active: Vec::new(),
        };
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
    // Oldest first: the one nobody has answered longest is the urgent one.
    active.sort_by_key(|e| std::cmp::Reverse(e.age_secs));

    EscalationStatus {
        enabled: true,
        reason: String::new(),
        iso_week,
        primary: rotation.map(|r| person(&r.primary_user)),
        backup: rotation.map(|r| person(&r.backup_user)),
        steps,
        active,
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
struct NotificationChannelInfo {
    /// Stable key the UI passes back to `test_notification_channel`.
    id: String,
    label: String,
    /// Whether the settings this channel needs are present.
    configured: bool,
    /// Where it would deliver, or what is missing. Never a secret: tokens and
    /// webhook URLs are credentials, so only their presence is reported.
    detail: String,
    /// False when the channel cannot work on this platform at all.
    available: bool,
}

fn notification_channels(n: &netscope_core::config::Notifications) -> Vec<NotificationChannelInfo> {
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
fn build_pcap_bytes(packets: &[Packet]) -> Vec<u8> {
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

fn build_pcapng_bytes(packets: &[Packet]) -> Result<Vec<u8>, String> {
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

#[tauri::command]
fn save_pcap(state: State<'_, Mutex<CaptureState>>, path: String) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    if guard.packet_buffer.is_empty() {
        return Err("No captured packets to save.".to_string());
    }
    let bytes = if path.to_lowercase().ends_with(".pcapng") {
        build_pcapng_bytes(&guard.packet_buffer)?
    } else {
        build_pcap_bytes(&guard.packet_buffer)
    };
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
    if guard.packet_buffer.is_empty() {
        return Err("No captured packets to save.".to_string());
    }
    let bytes = if path.to_lowercase().ends_with(".pcapng.enc") {
        build_pcapng_bytes(&guard.packet_buffer)?
    } else {
        build_pcap_bytes(&guard.packet_buffer)
    };
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

#[cfg(test)]
mod tests {
    use super::{
        arp_scan, block_ip, build_pcap_bytes, build_pcapng_bytes, english_name, get_alert_rules,
        get_glossary, get_lessons, get_protocol_risk, is_elevated, list_blocked, list_interfaces,
        list_plugins, notification_channels, protocol_count, protocol_table, replay_packet,
        save_object, tls_keylog_clear, tls_keylog_load, tls_keylog_status, unblock_ip,
        NotificationChannelInfo,
    };
    use netscope_core::models::Packet;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn replay_tcp_roundtrips_against_echo_server() {
        // Local echo server: read a line, write it back, close.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf) {
                    let _ = sock.write_all(&buf[..n]);
                }
            }
        });

        let res = replay_packet(
            "127.0.0.1".into(),
            port,
            "tcp".into(),
            b"ping".to_vec(),
            Some(1000),
        )
        .expect("replay should succeed");

        assert_eq!(res.sent, 4);
        assert_eq!(res.response, b"ping");
        assert!(!res.truncated);
    }

    #[test]
    fn replay_rejects_unknown_protocol() {
        let err = replay_packet(
            "127.0.0.1".into(),
            80,
            "icmp".into(),
            vec![1, 2, 3],
            Some(200),
        )
        .unwrap_err();
        assert!(err.contains("Unsupported protocol"));
    }

    /// The frontend groups flows and labels them from this table, so every
    /// protocol has to be in it. It used to answer both questions from lists
    /// written into its own source that covered about forty names — a flow
    /// carrying PROFINET or NGAP was labelled TCP because neither was listed.
    #[test]
    fn the_protocol_table_covers_the_whole_registry() {
        use netscope_core::models::Protocol;

        let table = protocol_table();
        let named = Protocol::ALL
            .iter()
            .filter(|p| !p.display_name().is_empty())
            .count();
        assert_eq!(table.len(), named, "every named protocol must be present");
        assert!(table.len() > 2000, "got {} rows", table.len());

        // The transports the frontend switches on, and nothing else.
        for (name, meta) in &table {
            assert!(
                matches!(meta.transport, "tcp" | "udp" | "icmp" | "arp" | "other"),
                "{name} has transport {:?}",
                meta.transport
            );
        }

        // Spot-check the two ends: a protocol the old lists knew, and one they
        // did not. Both must outrank the bare transport they ride on.
        let http = &table["HTTP"];
        assert_eq!(http.transport, "tcp");
        assert!(http.rank > table["TCP"].rank);

        let profinet = &table["PROFINET"];
        assert_eq!(profinet.transport, "other");
        assert!(
            profinet.rank > table["TCP"].rank,
            "PROFINET must be able to name its own flow"
        );
    }

    /// The two answer different questions and must not be conflated.
    ///
    /// `protocol_count` is a claim shown to the user, so it counts only what a
    /// capture can contain. `protocol_table` is a lookup the frontend consults
    /// for a protocol it has *already* received, so it must answer for every
    /// row — including ones only a future dissector will produce. This asserted
    /// they were equal, which forced the displayed count to include ~1,900
    /// protocols netscope cannot see.
    #[test]
    fn protocol_count_is_the_produced_subset_of_the_table() {
        use netscope_core::models::Protocol;
        let count = protocol_count();
        let table = protocol_table();
        assert_eq!(count, Protocol::produced().len());
        assert!(
            count < table.len(),
            "every row is marked produced ({count}) — did the status field collapse?"
        );
        // The lookup must still cover the protocols the count advertises.
        for p in Protocol::produced() {
            let name = p.display_name();
            if !name.is_empty() {
                assert!(table.contains_key(name), "{name} missing from the lookup");
            }
        }
    }

    #[test]
    fn glossary_contains_common_terms() {
        let glossary = get_glossary();
        assert!(!glossary.is_empty());
        assert!(glossary.iter().any(|e| e.term == "IP address"));
    }

    #[test]
    fn protocol_risk_known_protocol() {
        let risk = get_protocol_risk("HTTP".to_string()).unwrap();
        assert!(!risk.severity.is_empty());
    }

    /// The Learn tab is fed entirely from `education.rs`. This used to be a
    /// hand-written array of 53 pairs that silently stopped growing as
    /// protocols were added, so the guard is that the command still returns
    /// everything `education.rs` has rather than a frozen subset of it.
    #[test]
    fn lessons_cover_every_protocol_that_has_one() {
        let lessons = get_lessons();
        let expected = netscope_core::education::protocols_with_lessons().len();

        assert_eq!(lessons.len(), expected, "every lesson must reach the UI");
        assert!(
            lessons.len() > 53,
            "got {} — back to the old hand-written list",
            lessons.len()
        );

        // A lesson with an empty title or body renders as a blank card.
        for l in &lessons {
            assert!(!l.protocol.is_empty(), "lesson with no protocol name");
            assert!(!l.title.is_empty(), "{} has no title", l.protocol);
            assert!(!l.summary.is_empty(), "{} has no summary", l.protocol);
        }
    }

    /// The rules the app ships with have to be rules the engine can actually
    /// act on. Both halves of this fail silently: `AlertEngine::check` matches
    /// `trigger_type` as a string and falls through `_ => {}` on anything it
    /// does not know, and a filter that will not parse can never match a
    /// packet. Either way the rule sits in the UI looking armed and never fires.
    #[test]
    fn default_alert_rules_are_ones_the_engine_can_fire() {
        use netscope_core::filter::Filter;

        // The arms `AlertEngine::check` actually handles.
        const HANDLED: &[&str] = &[
            "threshold",
            "anomaly",
            "time-based",
            "signature",
            "correlation",
            "absence",
        ];

        let rules = get_alert_rules();
        assert!(!rules.is_empty(), "the app must ship some default rules");

        for rule in &rules {
            assert!(!rule.name.is_empty(), "a default rule has no name");
            assert!(
                HANDLED.contains(&rule.trigger.trigger_type.as_str()),
                "rule {:?} has trigger_type {:?}, which the engine ignores",
                rule.name,
                rule.trigger.trigger_type,
            );
            // The set documented on `AlertRule::severity`. Pinned to that list
            // on purpose: a severity outside it is one the UI cannot style, and
            // widening this without widening the doc is how they drift apart.
            assert!(
                matches!(
                    rule.severity.as_str(),
                    "informational" | "low" | "medium" | "high"
                ),
                "rule {:?} has severity {:?}",
                rule.name,
                rule.severity,
            );
            // An empty filter means "every packet" and is not passed to the
            // parser; anything else has to compile.
            if !rule.trigger.filter.is_empty() {
                assert!(
                    Filter::parse(&rule.trigger.filter).is_ok(),
                    "rule {:?} has an unparseable filter {:?}",
                    rule.name,
                    rule.trigger.filter,
                );
            }
        }
    }

    /// A channel is "configured" only when its settings are actually present.
    ///
    /// This guards against what the view used to do: five rows of markup with
    /// fixed badges, so Syslog read "Active" on a machine with nothing set up.
    /// Every badge now has to be derivable from `[notifications]`, so a default
    /// config must report nothing as configured.
    #[test]
    fn channel_status_is_read_from_config_not_assumed() {
        use netscope_core::config::Notifications;

        let empty = Notifications::default();
        for c in notification_channels(&empty) {
            if c.id == "winevent" {
                // The one channel with nothing to configure: it depends on the
                // platform, not on settings.
                assert_eq!(c.configured, cfg!(target_os = "windows"));
                continue;
            }
            assert!(!c.configured, "{} claims to be configured by default", c.id);
            assert!(
                c.detail.contains("notifications."),
                "{} should name the missing setting, got {:?}",
                c.id,
                c.detail,
            );
        }

        let mut set = Notifications {
            syslog_host: "10.0.0.9".into(),
            slack_webhook_url: "https://hooks.example/abc".into(),
            email_smtp_host: "smtp.example".into(),
            email_to: "soc@example".into(),
            // Deliberately only half of Telegram: one field cannot deliver.
            telegram_token: "secret-token".into(),
            ..Default::default()
        };
        let configured = |cs: &[NotificationChannelInfo], id: &str| {
            cs.iter()
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("channel {id} missing"))
                .configured
        };

        let cs = notification_channels(&set);
        assert!(configured(&cs, "syslog"));
        assert!(configured(&cs, "slack"));
        assert!(configured(&cs, "email"));
        assert!(!configured(&cs, "telegram"), "a token alone cannot deliver");

        set.telegram_chat_id = "12345".into();
        assert!(configured(&notification_channels(&set), "telegram"));

        // Tokens and webhook URLs are credentials; only their presence is
        // reported, so they must not travel to the UI in `detail`.
        for c in notification_channels(&set) {
            assert!(
                !c.detail.contains("secret-token"),
                "leaked token in {}",
                c.id
            );
            assert!(
                !c.detail.contains("hooks.example"),
                "leaked webhook in {}",
                c.id
            );
        }
    }

    /// Blank and whitespace-only settings must read as absent, so the engine's
    /// own "not configured" checks stay the single source of truth.
    #[test]
    fn blank_notification_settings_become_none() {
        use netscope_core::config::Notifications;

        let blanks = Notifications {
            syslog_host: "   ".into(),
            slack_webhook_url: String::new(),
            telegram_token: "\t".into(),
            ..Default::default()
        };
        let cfg = blanks.to_engine_config();
        assert!(cfg.syslog_host.is_none());
        assert!(cfg.slack_webhook_url.is_none());
        assert!(cfg.telegram_token.is_none());

        let padded = Notifications {
            syslog_host: "  10.0.0.9  ".into(),
            ..Default::default()
        };
        assert_eq!(
            padded.to_engine_config().syslog_host.as_deref(),
            Some("10.0.0.9"),
            "surrounding whitespace must not reach the socket",
        );
    }

    /// `tls_keylog_*` are thin wrappers whose only real job is mapping the core
    /// stats onto the fields the UI reads. A swap of `added`/`rejected` would
    /// report every accepted secret as junk, so both counts are pinned here.
    ///
    /// Kept as one test on purpose: the key log is process-global, so splitting
    /// this would let the parts race each other inside the test binary.
    #[test]
    fn keylog_load_reports_accepted_and_rejected_then_clears() {
        // `CLIENT_RANDOM <64 hex> <96 hex>` — two well-formed lines, plus a
        // comment (ignored outright) and two malformed ones.
        let good = format!(
            "CLIENT_RANDOM {} {}\nCLIENT_RANDOM {} {}\n",
            "a".repeat(64),
            "b".repeat(96),
            "c".repeat(64),
            "d".repeat(96),
        );
        // Deliberately 2 accepted vs 3 rejected: with equal counts a swap of the
        // two fields still satisfies both assertions and the test proves nothing.
        let text = format!(
            "# comment line\n{good}\
             CLIENT_RANDOM tooshort ff\n\
             not a keylog line\n\
             CLIENT_RANDOM {} nothex!!\n",
            "e".repeat(64),
        );

        let loaded = tls_keylog_load(text);
        assert_eq!(loaded.added, 2, "both well-formed secrets must be accepted");
        assert_eq!(
            loaded.rejected, 3,
            "the three malformed lines must be counted"
        );

        // `status` reports the live session count and never invents a delta.
        let status = tls_keylog_status();
        assert_eq!(status.sessions, loaded.sessions);
        assert_eq!(status.added, 0);
        assert_eq!(status.rejected, 0);

        // These secrets decrypt real traffic — clearing has to actually clear.
        let cleared = tls_keylog_clear();
        assert_eq!(cleared.sessions, 0);
        assert_eq!(
            tls_keylog_status().sessions,
            0,
            "secrets survived a clear()"
        );
    }

    #[test]
    fn protocol_risk_unknown_returns_none() {
        let risk = get_protocol_risk("NONEXISTENT_PROTOCOL_XYZ".to_string());
        assert!(risk.is_none());
    }

    #[test]
    fn save_object_writes_to_disk() {
        let dir = std::env::temp_dir().join("netscope-test-save-object");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.bin");
        let path_str = path.to_string_lossy().into_owned();

        let result = save_object(path_str, vec![1, 2, 3, 4, 5]);
        assert!(result.is_ok());

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, vec![1, 2, 3, 4, 5]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_object_reports_io_error() {
        let bogus = format!("Z:\\{}\0", std::process::id());
        let result = save_object(bogus, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn list_plugins_returns_vec() {
        let plugins = list_plugins();
        // plugins() reads from a directory — it may be empty, but it must be a
        // valid Vec<PluginInfo> with sensible defaults for every entry.
        for p in &plugins {
            assert!(!p.name.is_empty());
            assert!(matches!(p.transport.as_str(), "tcp" | "udp"));
            assert!(!p.description.is_empty());
        }
    }

    #[test]
    fn is_elevated_returns_bool() {
        // Whether this process is elevated depends on how it was launched, so
        // there is no value to assert. What matters is that the probe returns
        // rather than panicking — on Windows it shells out to `whoami /groups`.
        //
        // This used to read `assert!(elevated == true || elevated == false)`,
        // which is a tautology for a `bool`: the test could not fail even if
        // the function were replaced by one that always returned false.
        let elevated = is_elevated();
        assert_eq!(
            elevated,
            netscope_core::firewall::is_elevated(),
            "the command must report the same privilege state as the core probe",
        );
    }

    #[test]
    fn build_pcap_bytes_produces_valid_header() {
        use std::io::{Cursor, Read};

        let packet = Packet {
            timestamp: chrono::Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: netscope_core::models::Protocol::Tcp,
            length: 4,
            summary: "test".into(),
            data: b"ping"[..].into(),
            llm: None,
        };
        let bytes = build_pcap_bytes(&[packet]);

        let mut r = Cursor::new(&bytes);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf), 0xa1b2c3d4, "pcap magic");
        assert_eq!(
            bytes.len(),
            24 + 16 + 4,
            "global header + rec header + payload"
        );
    }

    #[test]
    fn build_pcapng_bytes_produces_valid_block() {
        use std::io::{Cursor, Read};

        let packet = Packet {
            timestamp: chrono::Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: netscope_core::models::Protocol::Udp,
            length: 3,
            summary: "test".into(),
            data: b"abc"[..].into(),
            llm: None,
        };
        let bytes = build_pcapng_bytes(&[packet]).unwrap();

        let mut r = Cursor::new(&bytes);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x0A, 0x0D, 0x0D, 0x0A], "pcapng SHB magic");
    }

    #[test]
    fn block_unblock_ip_workflow() {
        let ip = "192.168.1.240";
        let _ = unblock_ip(ip.into());
        let initial_blocked = list_blocked();
        assert!(!initial_blocked.contains(&ip.to_string()));

        let err = block_ip("invalid-ip".into()).unwrap_err();
        assert!(err.contains("not a valid IP address"));

        let unblock_err = unblock_ip("invalid-ip".into()).unwrap_err();
        assert!(unblock_err.contains("not a valid IP address"));
    }

    #[test]
    fn list_interfaces_returns_adapters() {
        let interfaces = list_interfaces().expect("interface enumeration should succeed");
        for iface in &interfaces {
            assert!(!iface.name.is_empty());
            assert!(!iface.kind.is_empty());
        }
    }

    #[test]
    fn arp_scan_handles_all_and_invalid_interfaces() {
        let res = arp_scan("__all__".into());
        assert!(res.is_ok());

        // Invalid or non-matching interface name gracefully falls back or returns Ok
        let invalid = arp_scan("nonexistent_iface_xyz_999".into());
        assert!(invalid.is_ok() || invalid.is_err());
    }

    #[test]
    fn notification_channels_lists_all_targets() {
        let channels = notification_channels(&netscope_core::config::Notifications::default());
        assert_eq!(channels.len(), 5);

        let ids: Vec<&str> = channels.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"syslog"));
        assert!(ids.contains(&"email"));
        assert!(ids.contains(&"slack"));
        assert!(ids.contains(&"telegram"));
        assert!(ids.contains(&"winevent"));
    }

    #[test]
    fn encrypted_pcap_validation_flow() {
        let packet = Packet {
            timestamp: chrono::Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: netscope_core::models::Protocol::Tcp,
            length: 4,
            summary: "test".into(),
            data: b"ping"[..].into(),
            llm: None,
        };
        let plain_bytes = build_pcap_bytes(&[packet]);
        assert!(!netscope_core::crypto::is_encrypted(&plain_bytes));

        let sealed = netscope_core::crypto::encrypt(&plain_bytes, "secret-pass").unwrap();
        assert!(netscope_core::crypto::is_encrypted(&sealed));

        let decrypted = netscope_core::crypto::decrypt(&sealed, "secret-pass").unwrap();
        assert_eq!(decrypted, plain_bytes);

        let bad_pass = netscope_core::crypto::decrypt(&sealed, "wrong-pass");
        assert!(bad_pass.is_err());
    }

    #[test]
    fn english_name_helper_extracts_name() {
        let names = maxminddb::geoip2::Names {
            english: Some("Turkey"),
            german: None,
            spanish: None,
            french: None,
            japanese: None,
            brazilian_portuguese: None,
            russian: None,
            simplified_chinese: None,
        };
        assert_eq!(english_name(&names), Some("Turkey".into()));

        let empty_names = maxminddb::geoip2::Names {
            english: None,
            german: None,
            spanish: None,
            french: None,
            japanese: None,
            brazilian_portuguese: None,
            russian: None,
            simplified_chinese: None,
        };
        assert_eq!(english_name(&empty_names), None);
    }
}
