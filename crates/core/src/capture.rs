use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::dissectors::{self, DissectedResult};
use crate::models::Packet;

pub fn list_interfaces() -> Result<Vec<pcap::Device>> {
    pcap::Device::list().context("Failed to list network interfaces.\n  On Windows: Install Npcap from https://npcap.com\n  On Linux/macOS: Run with sudo or set CAP_NET_RAW capability")
}

pub struct CaptureEngine {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Default for CaptureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureEngine {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    pub fn start_live(
        &mut self,
        interface: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let mut cap = pcap::Capture::from_device(interface)
            .map_err(|e| {
                if cfg!(target_os = "windows") {
                    anyhow::anyhow!(
                        "Failed to open interface '{interface}': {e}\n  Ensure Npcap is installed: https://npcap.com"
                    )
                } else if cfg!(unix) {
                    anyhow::anyhow!(
                        "Failed to open interface '{interface}': {e}\n  Run with sudo or set CAP_NET_RAW capability"
                    )
                } else {
                    anyhow::anyhow!("Failed to open interface '{interface}': {e}")
                }
            })?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| {
                if cfg!(target_os = "windows") {
                    anyhow::anyhow!(
                        "Failed to open capture on '{interface}': {e}\n  Ensure Npcap is installed and WinPcap is not conflicting"
                    )
                } else {
                    anyhow::anyhow!("Failed to open capture on '{interface}': {e}")
                }
            })?;

        if let Some(filter) = bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
        }

        let output_path = output_path.map(|s| s.to_string());

        let handle = thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                let mut savefile = output_path
                    .as_ref()
                    .and_then(|path| match cap.savefile(path) {
                        Ok(sf) => Some(sf),
                        Err(e) => {
                            eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
                            None
                        }
                    });
                while running.load(Ordering::SeqCst) {
                    match cap.next_packet() {
                        Ok(pkt) => {
                            if let Some(ref mut sf) = savefile {
                                sf.write(&pkt);
                            }
                            let packet = build_packet(pkt);
                            if packet_tx.send(packet).is_err() {
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(pcap::Error::NoMorePackets) => break,
                        Err(e) => {
                            eprintln!("Capture error: {e}");
                            break;
                        }
                    }
                }
            })
            .context("Failed to spawn capture thread")?;

        self.handle = Some(handle);
        Ok(())
    }

    pub fn start_offline(
        &mut self,
        filepath: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let mut cap = pcap::Capture::from_file(filepath)
            .map_err(|e| anyhow::anyhow!("Failed to open pcap file '{filepath}': {e}"))?;

        if let Some(filter) = bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
        }

        let output_path = output_path.map(|s| s.to_string());

        let handle = thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                let mut savefile = output_path
                    .as_ref()
                    .and_then(|path| match cap.savefile(path) {
                        Ok(sf) => Some(sf),
                        Err(e) => {
                            eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
                            None
                        }
                    });
                while running.load(Ordering::SeqCst) {
                    match cap.next_packet() {
                        Ok(pkt) => {
                            if let Some(ref mut sf) = savefile {
                                sf.write(&pkt);
                            }
                            let packet = build_packet(pkt);
                            if packet_tx.send(packet).is_err() {
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(pcap::Error::NoMorePackets) => break,
                        Err(e) => {
                            eprintln!("Capture error: {e}");
                            break;
                        }
                    }
                }
            })
            .context("Failed to spawn capture thread")?;

        self.handle = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn build_packet(pkt: pcap::Packet) -> Packet {
    let timestamp = chrono::DateTime::from_timestamp(
        pkt.header.ts.tv_sec as i64,
        pkt.header.ts.tv_usec as u32 * 1000,
    )
    .unwrap_or_default();

    let DissectedResult {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        summary,
    } = dissectors::dissect(pkt.data);

    Packet {
        timestamp,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        length: pkt.header.len as usize,
        summary,
        data: pkt.data.to_vec(),
    }
}
