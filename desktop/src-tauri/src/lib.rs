use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use netscope_core::capture::CaptureEngine;
use netscope_core::models::Packet;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

struct CaptureState {
    engine: Option<CaptureEngine>,
    running: AtomicBool,
    packet_buffer: Vec<Packet>,
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
    src_addr: Option<String>,
    dst_addr: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: String,
    length: usize,
    summary: String,
    raw: Vec<u8>,
}

fn packet_to_info(pkt: Packet) -> PacketInfo {
    PacketInfo {
        raw: pkt.data.clone(),
        timestamp: pkt.timestamp.format("%H:%M:%S%.3f").to_string(),
        src_addr: pkt.src_addr.map(|a| a.to_string()),
        dst_addr: pkt.dst_addr.map(|a| a.to_string()),
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        protocol: pkt.protocol.to_string(),
        length: pkt.length,
        summary: pkt.summary,
    }
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
                let info = packet_to_info(pkt.clone());
                let _ = app_handle.emit("packet", info);
                // Buffer for save_pcap
                if let Ok(mut g) = app_handle.state::<Mutex<CaptureState>>().lock() {
                    g.packet_buffer.push(pkt);
                    if g.packet_buffer.len() > 100_000 {
                        g.packet_buffer.drain(..50_000);
                    }
                }
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
            let info = packet_to_info(pkt.clone());
            let _ = app_handle.emit("packet", info);
            // Buffer for save_pcap
            if let Ok(mut g) = app_handle.state::<Mutex<CaptureState>>().lock() {
                g.packet_buffer.push(pkt);
                if g.packet_buffer.len() > 100_000 {
                    g.packet_buffer.drain(..50_000);
                }
            }
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
            _packet_count: 0,
        }))
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture,
            open_pcap,
            save_pcap,
        ])
        .run(tauri::generate_context!())
        .expect("error while running netscope desktop");
}
