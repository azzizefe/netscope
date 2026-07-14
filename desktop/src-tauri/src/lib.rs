use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

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
    use netscope_core::models::Protocol;
    let protos = [
        ("DNS", Protocol::Dns),
        ("TCP", Protocol::Tcp),
        ("TLS", Protocol::Tls),
        ("HTTP", Protocol::Http),
        ("UDP", Protocol::Udp),
        ("ICMP", Protocol::Icmp),
        ("ARP", Protocol::Arp),
        ("DHCP", Protocol::Dhcp),
        ("NTP", Protocol::Ntp),
        ("mDNS", Protocol::Mdns),
        ("SNMP", Protocol::Snmp),
        ("QUIC", Protocol::Quic),
        ("SIP", Protocol::Sip),
        ("SSH", Protocol::Ssh),
        ("FTP", Protocol::Ftp),
        ("SMTP", Protocol::Smtp),
        ("IMAP", Protocol::Imap),
        ("POP3", Protocol::Pop3),
        ("Telnet", Protocol::Telnet),
        ("RDP", Protocol::Rdp),
        ("WebSocket", Protocol::WebSocket),
        ("HTTP/2", Protocol::Http2),
        ("gRPC", Protocol::Grpc),
        ("VXLAN", Protocol::Vxlan),
        ("PostgreSQL", Protocol::Postgres),
        ("MySQL", Protocol::Mysql),
        ("MongoDB", Protocol::Mongodb),
        ("Redis", Protocol::Redis),
        ("Cassandra", Protocol::Cassandra),
        ("Modbus", Protocol::Modbus),
        ("DNP3", Protocol::Dnp3),
        ("BACnet", Protocol::Bacnet),
        ("EtherNet/IP", Protocol::Enip),
        ("OPC UA", Protocol::OpcUa),
        ("RTP", Protocol::Rtp),
        ("RTCP", Protocol::Rtcp),
        ("Kerberos", Protocol::Kerberos),
        ("LDAP", Protocol::Ldap),
        ("RADIUS", Protocol::Radius),
        ("OpenVPN", Protocol::OpenVpn),
        ("WireGuard", Protocol::WireGuard),
        ("ESP", Protocol::Esp),
        ("AH", Protocol::Ah),
        ("MQTT", Protocol::Mqtt),
        ("CoAP", Protocol::Coap),
        ("BGP", Protocol::Bgp),
        ("OSPF", Protocol::Ospf),
        ("LLDP", Protocol::Lldp),
        ("LACP", Protocol::Lacp),
        ("STP", Protocol::Stp),
        ("MPLS", Protocol::Mpls),
        ("802.11", Protocol::Wlan),
        ("Unknown", Protocol::Unknown(String::new())),
    ];
    protos
        .iter()
        .map(|(name, p)| {
            let l = netscope_core::education::lesson(p);
            LessonInfo {
                protocol: name.to_string(),
                title: l.title.to_string(),
                summary: l.summary.to_string(),
                body: l.body.to_string(),
                look_for: l.look_for.to_string(),
            }
        })
        .collect()
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
            let kind = netscope_core::capture::interface_kind(&d).as_str().to_string();
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
                return Err(
                    "A ring buffer needs a file size or duration to rotate on.".to_string()
                );
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
    drop(guard);

    let app_handle = app.clone();
    std::thread::spawn(move || {
        loop {
            match packet_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(pkt) => {
                    let info = if let Ok(mut g) = app_handle.state::<Mutex<CaptureState>>().lock() {
                        // Learn hostnames from DNS, then resolve this packet's addrs.
                        g.names.observe(&pkt);
                        let info = packet_to_info(&pkt, &g.names);
                        g.packet_buffer.push(pkt);
                        if g.packet_buffer.len() > 100_000 {
                            g.packet_buffer.drain(..50_000);
                        }
                        info
                    } else {
                        packet_to_info(&pkt, &NameCache::new())
                    };
                    let _ = app_handle.emit("packet", info);
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
        // The channel only disconnects when every capture pipeline has
        // drained — either a manual stop or the engine stopping itself
        // (autostop, stream end). Tell the UI either way; it ignores the
        // event when it already knows the capture is over.
        let _ = app_handle.emit("capture-stopped", ());
    });

    Ok(())
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
    let infos: Vec<PacketInfo> = if let Ok(mut g) = app.state::<Mutex<CaptureState>>().lock() {
        for pkt in &batch {
            g.names.observe(pkt);
        }
        let infos = batch.iter().map(|p| packet_to_info(p, &g.names)).collect();
        g.packet_buffer.extend(batch);
        if g.packet_buffer.len() > 100_000 {
            let excess = g.packet_buffer.len() - 50_000;
            g.packet_buffer.drain(..excess);
        }
        infos
    } else {
        let names = NameCache::new();
        batch.iter().map(|p| packet_to_info(p, &names)).collect()
    };
    let _ = app.emit("packets-batch", infos);
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
    ).map_err(|e| e.to_string())?;

    for pkt in packets {
        let ts_sec = pkt.timestamp.timestamp();
        let ts_nanos = pkt.timestamp.timestamp_subsec_nanos();
        writer.write_packet(0, ts_sec, ts_nanos, pkt.length as u32, &pkt.data, None)
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
        }))
        .manage(Mutex::new(geo))
        .manage(Mutex::new(config_state))
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            start_remote_capture,
            stop_capture,
            open_pcap,
            open_pcap_encrypted,
            save_pcap,
            save_pcap_encrypted,
            get_lessons,
            get_glossary,
            is_elevated,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running netscope desktop");
}

#[cfg(test)]
mod tests {
    use super::replay_packet;
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
}
