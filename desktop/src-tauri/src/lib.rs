use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use netscope_core::capture::CaptureEngine;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;
use serde::Serialize;
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
        raw: pkt.data.clone(),
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
    Ok(devices
        .into_iter()
        .map(|d| InterfaceInfo {
            name: d.name,
            description: d.desc.unwrap_or_default(),
        })
        .collect())
}

#[tauri::command]
fn start_capture(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    interface: String,
    filter: Option<String>,
    output_path: Option<String>,
) -> Result<(), String> {
    let mut capture = CaptureEngine::new();
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let bpf_filter = filter.as_deref();
    let output = output_path.as_deref();

    capture
        .start_live(&interface, bpf_filter, output, packet_tx)
        .map_err(|e| e.to_string())?;

    let mut guard = state.lock().map_err(|e| e.to_string())?;
    guard.engine = Some(capture);
    guard.running.store(true, Ordering::SeqCst);

    // Spawn packet forwarder — exits when channel disconnects (capture stops)
    let app_handle = app.clone();
    std::thread::spawn(move || loop {
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
    });

    Ok(())
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

#[tauri::command]
fn open_pcap(
    app: AppHandle,
    state: State<'_, Mutex<CaptureState>>,
    path: String,
) -> Result<(), String> {
    let mut capture = CaptureEngine::new();
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();

    capture
        .start_offline(&path, None, None, packet_tx)
        .map_err(|e| e.to_string())?;

    let mut guard = state.lock().map_err(|e| e.to_string())?;
    guard.engine = Some(capture);

    let app_handle = app.clone();
    std::thread::spawn(move || {
        while let Ok(pkt) = packet_rx.recv() {
            let info = if let Ok(mut g) = app_handle.state::<Mutex<CaptureState>>().lock() {
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
        let _ = app_handle.emit("capture-finished", ());
    });

    Ok(())
}

#[tauri::command]
fn save_pcap(state: State<'_, Mutex<CaptureState>>, path: String) -> Result<(), String> {
    use std::io::Write;

    let guard = state.lock().map_err(|e| e.to_string())?;
    if guard.packet_buffer.is_empty() {
        return Err("No captured packets to save.".to_string());
    }

    let mut file =
        std::fs::File::create(&path).map_err(|e| format!("Failed to create '{path}': {e}"))?;

    // Write pcap global header (24 bytes)
    let magic: u32 = 0xa1b2c3d4; // microsecond resolution
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    let thiszone: i32 = 0; // timezone offset (UTC)
    let sigfigs: u32 = 0;
    let snaplen: u32 = 65535;
    let network: u32 = 1; // Ethernet

    let global_header = [
        &magic.to_ne_bytes()[..],
        &version_major.to_ne_bytes()[..],
        &version_minor.to_ne_bytes()[..],
        &thiszone.to_ne_bytes()[..],
        &sigfigs.to_ne_bytes()[..],
        &snaplen.to_ne_bytes()[..],
        &network.to_ne_bytes()[..],
    ]
    .concat();
    file.write_all(&global_header)
        .map_err(|e| format!("Failed to write pcap header: {e}"))?;

    for pkt in &guard.packet_buffer {
        let ts_sec = pkt.timestamp.timestamp() as u32;
        let ts_usec = pkt.timestamp.timestamp_subsec_micros();
        let incl_len = pkt.length as u32;
        let orig_len = pkt.length as u32;

        let pkt_header = [
            &ts_sec.to_ne_bytes()[..],
            &ts_usec.to_ne_bytes()[..],
            &incl_len.to_ne_bytes()[..],
            &orig_len.to_ne_bytes()[..],
        ]
        .concat();
        file.write_all(&pkt_header)
            .map_err(|e| format!("Failed to write packet header: {e}"))?;
        file.write_all(&pkt.data)
            .map_err(|e| format!("Failed to write packet data: {e}"))?;
    }

    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(CaptureState {
            engine: None,
            running: AtomicBool::new(false),
            packet_buffer: Vec::new(),
            names: NameCache::new(),
            _packet_count: 0,
        }))
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture,
            open_pcap,
            save_pcap,
            get_lessons,
            get_glossary,
            is_elevated,
            list_blocked,
            block_ip,
            unblock_ip,
            replay_packet,
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
