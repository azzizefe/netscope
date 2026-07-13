use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::models::Packet;
use crate::pipeline::{Pipeline, RawFrame, StatsSnapshot};

/// Translate human-friendly protocol names in a filter expression into valid
/// BPF syntax. Tokens that are already valid BPF (ports, hostnames, operators)
/// are left untouched, so "http or tls" becomes "tcp port 80 or tcp port 443".
pub fn translate_bpf_filter(raw: &str) -> String {
    // Longer names first so "https" is matched before "http".
    const MAP: &[(&str, &str)] = &[
        // web
        ("https", "tcp port 443"),
        ("http", "tcp port 80"),
        ("tls", "tcp port 443"),
        ("ssl", "tcp port 443"),
        // mail
        ("smtps", "tcp port 465"),
        ("smtp", "tcp port 25"),
        ("imaps", "tcp port 993"),
        ("imap", "tcp port 143"),
        ("pop3s", "tcp port 995"),
        ("pop3", "tcp port 110"),
        // infrastructure
        ("dns", "udp port 53"),
        ("dhcp", "udp port 67 or udp port 68"),
        ("bootp", "udp port 67 or udp port 68"),
        ("ntp", "udp port 123"),
        ("snmp", "udp port 161"),
        ("ssh", "tcp port 22"),
        ("ftp", "tcp port 21"),
        ("telnet", "tcp port 23"),
        ("rdp", "tcp port 3389"),
        ("ldaps", "tcp port 636"),
        ("ldap", "tcp port 389"),
        // databases
        ("mysql", "tcp port 3306"),
        ("postgres", "tcp port 5432"),
        ("redis", "tcp port 6379"),
        ("mongodb", "tcp port 27017"),
        // already-valid BPF tokens — pass through (listed only so
        // sub-word matches like "icmp" inside "icmp6" are avoided)
        ("icmp6", "icmp6"),
        ("icmp", "icmp"),
        ("arp", "arp"),
    ];

    let mut result = String::with_capacity(raw.len() + 64);
    let mut i = 0;
    let bytes = raw.as_bytes();
    // When true, the next token is a hostname / address — skip protocol
    // translation. Set by the BPF keyword "host" and cleared after one token.
    let mut next_is_host = false;

    while i < bytes.len() {
        // Skip whitespace and parentheses verbatim.
        if bytes[i].is_ascii_whitespace() || bytes[i] == b'(' || bytes[i] == b')' {
            result.push(bytes[i] as char);
            i += 1;
            continue;
        }

        // Collect a token (letters, digits, underscore, dot, hyphen).
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'_'
                || bytes[i] == b'.'
                || bytes[i] == b'-')
        {
            i += 1;
        }
        let token = &raw[start..i];

        // If this token follows "host", it is a hostname — never
        // translate it. "host http.example.com" stays untouched.
        let replacement = if next_is_host {
            next_is_host = false;
            None
        } else {
            MAP.iter().find_map(|(k, v)| {
                if token.len() == k.len() && token.eq_ignore_ascii_case(k) {
                    Some(*v)
                } else {
                    None
                }
            })
        };

        match replacement {
            Some(r) => {
                result.push_str(r);
                // Replacement is valid BPF (e.g. "tcp port 80") — no
                // host-keyword tracking needed inside it.
            }
            None => {
                // Remember whether this token is the BPF "host" keyword
                // so the NEXT token isn't translated.
                if token.eq_ignore_ascii_case("host") {
                    next_is_host = true;
                }
                result.push_str(token);
            }
        }
    }

    result
}

pub fn list_interfaces() -> Result<Vec<pcap::Device>> {
    pcap::Device::list().context("Failed to list network interfaces.\n  On Windows: Install Npcap from https://npcap.com\n  On Linux/macOS: Run with sudo or set CAP_NET_RAW capability")
}

/// Pick the best interface for zero-config capture: a connected,
/// non-loopback device with a routable IPv4 address. Plain `.first()`
/// often lands on a WAN Miniport or virtual adapter that sees no traffic.
pub fn default_interface() -> Result<pcap::Device> {
    let devices = list_interfaces()?;
    devices
        .iter()
        .max_by_key(|d| interface_score(d))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No network interfaces found"))
}

fn interface_score(dev: &pcap::Device) -> i32 {
    let mut score = 0;
    if dev.flags.is_loopback() {
        return -100;
    }
    if dev.flags.connection_status == pcap::ConnectionStatus::Connected {
        score += 4;
    }
    if dev.flags.is_up() && dev.flags.is_running() {
        score += 2;
    }
    let has_routable_v4 = dev.addresses.iter().any(|a| match a.addr {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified()
        }
        _ => false,
    });
    if has_routable_v4 {
        score += 3;
    }
    // Virtual adapters (Hyper-V, VMware, WSL) rarely carry the user's traffic.
    if let Some(desc) = &dev.desc {
        let d = desc.to_lowercase();
        if d.contains("miniport") || d.contains("virtual") || d.contains("hyper-v") {
            score -= 3;
        }
    }
    score
}

/// Human-friendly label for a device: its description when available
/// (e.g. "Intel(R) Wi-Fi 6 AX201"), otherwise the raw name.
pub fn friendly_name(dev: &pcap::Device) -> String {
    dev.desc.clone().unwrap_or_else(|| dev.name.clone())
}

/// Look up the friendly label for a device by its raw name.
pub fn friendly_name_of(raw_name: &str) -> String {
    list_interfaces()
        .ok()
        .and_then(|devs| devs.iter().find(|d| d.name == raw_name).map(friendly_name))
        .unwrap_or_else(|| raw_name.to_string())
}

/// Open a live capture handle on `interface`, apply the (protocol-translated)
/// BPF filter, and return it with its link-layer type. Shared by single- and
/// multi-interface capture so both open interfaces identically.
fn open_live_capture(
    interface: &str,
    bpf_filter: Option<&str>,
    monitor: bool,
) -> Result<(pcap::Capture<pcap::Active>, i32)> {
    let inactive = pcap::Capture::from_device(interface)
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
        .timeout(1000);

    // Monitor (rfmon) mode captures raw 802.11 frames instead of Ethernet.
    // The `pcap` crate only exposes it on non-Windows platforms; on Windows,
    // Npcap monitor mode needs a separate driver API we don't bind, so we
    // fail clearly rather than silently capturing Ethernet.
    #[cfg(not(windows))]
    let inactive = inactive.rfmon(monitor);
    #[cfg(windows)]
    if monitor {
        return Err(anyhow::anyhow!(
            "Monitor mode (raw 802.11) isn't supported on Windows through netscope's capture backend.\n  Open a monitor-mode .pcap instead, or capture on Linux/macOS with a monitor-capable adapter."
        ));
    }

    let mut cap = inactive.open().map_err(|e| {
        if monitor {
            anyhow::anyhow!(
                "Failed to open '{interface}' in monitor mode: {e}\n  This adapter/driver may not support monitor mode. Turn it off under Wireless, or use a monitor-capable adapter."
            )
        } else if cfg!(target_os = "windows") {
            anyhow::anyhow!(
                "Failed to open capture on '{interface}': {e}\n  Ensure Npcap is installed and WinPcap is not conflicting"
            )
        } else {
            anyhow::anyhow!("Failed to open capture on '{interface}': {e}")
        }
    })?;

    if let Some(filter) = bpf_filter {
        let translated = translate_bpf_filter(filter);
        cap.filter(&translated, true)
            .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
    }

    let linktype = cap.get_datalink().0;
    Ok((cap, linktype))
}

/// Capture engine built on the parallel pipeline (ROADMAP §2.1): each capture
/// thread feeds raw frames into a lock-free ring, a rayon-backed dissector
/// stage parses them across cores, and finished [`Packet`]s arrive on the
/// `Sender` given to `start_live`/`start_live_multi`/`start_offline`. Capturing
/// on several interfaces at once runs one capture thread + pipeline per
/// interface, all merged onto the one `Sender` (Wireshark-style).
pub struct CaptureEngine {
    running: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
    pipelines: Vec<Pipeline>,
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
            handles: Vec::new(),
            pipelines: Vec::new(),
        }
    }

    pub fn start_live(
        &mut self,
        interface: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
        monitor: bool,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let (mut cap, linktype) = match open_live_capture(interface, bpf_filter, monitor) {
            Ok(v) => v,
            Err(e) => {
                running.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };

        let output_path = output_path.map(|s| s.to_string());

        // Dissection happens off the capture thread: frames go into the
        // lock-free ring, the pipeline's rayon stage parses them.
        let pipeline = Pipeline::start(linktype, packet_tx, running.clone());
        let producer = pipeline.producer();

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
                            // Live capture must never stall the wire loop:
                            // a full ring drops the frame (counted in stats).
                            producer.push_live(raw_frame(pkt));
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(pcap::Error::NoMorePackets) => break,
                        Err(e) => {
                            eprintln!("Capture error: {e}");
                            break;
                        }
                    }
                }
                producer.finish();
            })
            .context("Failed to spawn capture thread")?;

        self.handles.push(handle);
        self.pipelines.push(pipeline);
        Ok(())
    }

    /// Capture on several interfaces at once, merged into the one `packet_tx`
    /// (Wireshark-style multi-interface capture). Each interface gets its own
    /// capture thread and dissector pipeline, so mixed link types (Ethernet +
    /// Wi-Fi) are each dissected correctly. Interfaces that fail to open are
    /// skipped with a warning; it's an error only if *none* opens.
    ///
    /// A single interface delegates to [`start_live`](Self::start_live) (which
    /// also supports writing to a savefile). Writing to a file while capturing
    /// on multiple interfaces is not supported — classic pcap has one global
    /// link type — so `output_path` is ignored (with a warning) for >1.
    pub fn start_live_multi(
        &mut self,
        interfaces: &[&str],
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
        monitor: bool,
    ) -> Result<()> {
        if interfaces.is_empty() {
            anyhow::bail!("No capture interface specified.");
        }
        if interfaces.len() == 1 {
            return self.start_live(interfaces[0], bpf_filter, output_path, packet_tx, monitor);
        }
        if output_path.is_some() {
            eprintln!(
                "Warning: saving to a file isn't supported when capturing on multiple interfaces — the capture will not be written to disk."
            );
        }

        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        // Open every interface up front. Keep the ones that open; collect the
        // rest as warnings so one dead adapter doesn't sink the whole capture.
        let mut opened = Vec::new();
        let mut errors = Vec::new();
        for &iface in interfaces {
            match open_live_capture(iface, bpf_filter, monitor) {
                Ok((cap, linktype)) => opened.push((iface.to_string(), cap, linktype)),
                Err(e) => errors.push(format!("{e}")),
            }
        }
        if opened.is_empty() {
            running.store(false, Ordering::SeqCst);
            anyhow::bail!(
                "Could not open any of the requested interfaces:\n  {}",
                errors.join("\n  ")
            );
        }
        for e in &errors {
            eprintln!("Warning: skipping interface — {e}");
        }

        for (iface, mut cap, linktype) in opened {
            let tx = packet_tx.clone();
            let pipeline = Pipeline::start(linktype, tx, running.clone());
            let producer = pipeline.producer();
            let run = running.clone();
            let handle = thread::Builder::new()
                .name(format!("capture:{iface}"))
                .spawn(move || {
                    while run.load(Ordering::SeqCst) {
                        match cap.next_packet() {
                            Ok(pkt) => producer.push_live(raw_frame(pkt)),
                            Err(pcap::Error::TimeoutExpired) => continue,
                            Err(pcap::Error::NoMorePackets) => break,
                            Err(e) => {
                                eprintln!("Capture error on '{iface}': {e}");
                                break;
                            }
                        }
                    }
                    producer.finish();
                })
                .context("Failed to spawn capture thread")?;
            self.handles.push(handle);
            self.pipelines.push(pipeline);
        }
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
            let translated = translate_bpf_filter(filter);
            cap.filter(&translated, true)
                .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
        }

        let output_path = output_path.map(|s| s.to_string());
        // Link-layer type of the saved capture (Ethernet, 802.11, radiotap…).
        let linktype = cap.get_datalink().0;

        let pipeline = Pipeline::start(linktype, packet_tx, running.clone());
        let producer = pipeline.producer();

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
                            // Reading a file: block for ring space instead of
                            // dropping — losing packets from a pcap would
                            // silently skew analysis.
                            if !producer.push_blocking(raw_frame(pkt), &running) {
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
                producer.finish();
            })
            .context("Failed to spawn capture thread")?;

        self.handles.push(handle);
        self.pipelines.push(pipeline);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Join every capture thread first so all producers have declared their
        // streams finished…
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
        // …then wait for each dissector stage to drain its ring so no packet is
        // lost on stop. Pipelines stay around so their final stats remain readable.
        for pipeline in self.pipelines.iter_mut() {
            pipeline.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Pipeline counters (frames received / dropped / dissected) summed across
    /// every active interface. `None` before the first start.
    pub fn pipeline_stats(&self) -> Option<StatsSnapshot> {
        if self.pipelines.is_empty() {
            return None;
        }
        let mut agg = StatsSnapshot::default();
        for p in &self.pipelines {
            let s = p.stats();
            agg.received += s.received;
            agg.dropped += s.dropped;
            agg.dissected += s.dissected;
        }
        Some(agg)
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Convert a libpcap packet into the pipeline's raw-frame form. This is all
/// the capture thread does per packet — dissection happens downstream.
fn raw_frame(pkt: pcap::Packet) -> RawFrame {
    // tv_sec is i32 on Windows but already i64 on Linux/macOS, so the cast
    // is platform-necessary even where clippy flags it as i64 -> i64.
    #[allow(clippy::unnecessary_cast)]
    let ts_sec = pkt.header.ts.tv_sec as i64;
    RawFrame {
        ts_sec,
        ts_nanos: pkt.header.ts.tv_usec as u32 * 1000,
        orig_len: pkt.header.len,
        data: pkt.data.to_vec(),
    }
}

// ---- Async facade (feature = "async") --------------------------------------

/// Tokio-friendly wrapper around [`CaptureEngine`] for async consumers (the
/// planned REST/WebSocket server mode). The blocking pcap read loop and the
/// dissector stage stay on their dedicated OS threads — the roadmap's
/// zero-copy async I/O (AF_XDP) is a separate, Linux-only future step — and a
/// bridge thread forwards finished packets into a bounded tokio channel.
#[cfg(feature = "async")]
pub struct AsyncCaptureEngine {
    inner: CaptureEngine,
}

#[cfg(feature = "async")]
impl AsyncCaptureEngine {
    /// Start a live capture; packets arrive on the returned tokio receiver.
    /// `buffer` caps in-flight packets between the pipeline and the async
    /// consumer (lagging consumers apply backpressure to the bridge, never to
    /// the wire loop — the ring's drop policy handles overload there).
    pub fn start_live(
        interface: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        monitor: bool,
        buffer: usize,
    ) -> Result<(Self, tokio::sync::mpsc::Receiver<Packet>)> {
        let (std_tx, std_rx) = crossbeam_channel::unbounded();
        let mut inner = CaptureEngine::new();
        inner.start_live(interface, bpf_filter, output_path, std_tx, monitor)?;
        Ok((Self { inner }, bridge(std_rx, buffer)))
    }

    /// Read a capture file; packets arrive on the returned tokio receiver,
    /// and the channel closes after the last one.
    pub fn start_offline(
        filepath: &str,
        bpf_filter: Option<&str>,
        buffer: usize,
    ) -> Result<(Self, tokio::sync::mpsc::Receiver<Packet>)> {
        let (std_tx, std_rx) = crossbeam_channel::unbounded();
        let mut inner = CaptureEngine::new();
        inner.start_offline(filepath, bpf_filter, None, std_tx)?;
        Ok((Self { inner }, bridge(std_rx, buffer)))
    }

    /// Stop the capture and drain the pipeline. Blocks briefly (thread
    /// joins); call via `spawn_blocking` on latency-sensitive runtimes.
    pub fn stop(&mut self) {
        self.inner.stop();
    }

    /// See [`CaptureEngine::pipeline_stats`].
    pub fn pipeline_stats(&self) -> Option<StatsSnapshot> {
        self.inner.pipeline_stats()
    }
}

/// Forward packets from the pipeline's crossbeam channel into a bounded tokio
/// channel. Ends (and closes the tokio side) when the source disconnects.
#[cfg(feature = "async")]
fn bridge(
    std_rx: crossbeam_channel::Receiver<Packet>,
    buffer: usize,
) -> tokio::sync::mpsc::Receiver<Packet> {
    let (tx, rx) = tokio::sync::mpsc::channel(buffer.max(1));
    thread::Builder::new()
        .name("async-bridge".into())
        .spawn(move || {
            while let Ok(pkt) = std_rx.recv() {
                if tx.blocking_send(pkt).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn async bridge thread");
    rx
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;
    use crate::dissectors::test_helpers::build_tcp_packet;
    use crate::models::Protocol;

    /// Write a minimal little-endian classic pcap with `n` HTTP frames.
    fn write_test_pcap(n: usize) -> std::path::PathBuf {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        for i in 0..n {
            let frame = build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                12345,
                80,
                false,
                true,
                false,
                false,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            );
            buf.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            buf.extend_from_slice(&frame);
        }
        let path = std::env::temp_dir().join(format!(
            "netscope-async-capture-{}.pcap",
            std::process::id()
        ));
        std::fs::write(&path, buf).unwrap();
        path
    }

    #[test]
    fn async_offline_delivers_all_packets_then_closes() {
        let path = write_test_pcap(5);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut engine, mut rx) =
                AsyncCaptureEngine::start_offline(path.to_str().unwrap(), None, 4).unwrap();
            let mut count = 0;
            while let Some(pkt) = rx.recv().await {
                assert_eq!(pkt.protocol, Protocol::Http);
                count += 1;
            }
            assert_eq!(count, 5);
            engine.stop();
            let stats = engine.pipeline_stats().unwrap();
            assert_eq!(stats.dissected, 5);
            assert_eq!(stats.dropped, 0);
        });
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    #[test]
    fn multi_requires_at_least_one_interface() {
        let mut eng = CaptureEngine::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let err = eng
            .start_live_multi(&[], None, None, tx, false)
            .unwrap_err();
        assert!(err.to_string().contains("No capture interface"), "{err}");
        assert!(!eng.is_running());
    }

    #[test]
    fn multi_all_bogus_interfaces_errors_and_resets_running() {
        let mut eng = CaptureEngine::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        // Names that cannot resolve to real devices — every open fails, so the
        // whole call must error (and leave the engine stopped).
        let res = eng.start_live_multi(
            &["netscope-no-such-if-0", "netscope-no-such-if-1"],
            None,
            None,
            tx,
            false,
        );
        assert!(res.is_err());
        assert!(!eng.is_running());
        assert!(eng.pipeline_stats().is_none());
    }
}

#[cfg(test)]
mod filter_tests {
    use super::translate_bpf_filter;

    #[test]
    fn simple_http() {
        assert_eq!(translate_bpf_filter("http"), "tcp port 80");
        assert_eq!(translate_bpf_filter("HTTP"), "tcp port 80");
    }

    #[test]
    fn http_or_tls() {
        assert_eq!(
            translate_bpf_filter("http or tls"),
            "tcp port 80 or tcp port 443"
        );
    }

    #[test]
    fn compound_expression() {
        assert_eq!(
            translate_bpf_filter("http or tls or dns"),
            "tcp port 80 or tcp port 443 or udp port 53"
        );
    }

    #[test]
    fn parenthesized() {
        assert_eq!(
            translate_bpf_filter("(http or tls) and host 1.2.3.4"),
            "(tcp port 80 or tcp port 443) and host 1.2.3.4"
        );
    }

    #[test]
    fn already_valid_bpf_unchanged() {
        let bpf = "tcp port 80 or udp port 53";
        assert_eq!(translate_bpf_filter(bpf), bpf);
    }

    #[test]
    fn icmp_arp_pass_through() {
        assert_eq!(translate_bpf_filter("icmp or arp"), "icmp or arp");
    }

    #[test]
    fn https_takes_precedence_over_http() {
        // "https" must NOT become "tcp port 443s" (substring match bug).
        assert_eq!(translate_bpf_filter("https"), "tcp port 443");
    }

    #[test]
    fn mixed_ports_and_protocols() {
        assert_eq!(
            translate_bpf_filter("ssh or tcp port 8080"),
            "tcp port 22 or tcp port 8080"
        );
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(translate_bpf_filter(""), "");
        assert_eq!(translate_bpf_filter("  "), "  ");
    }

    #[test]
    fn host_keyword_protects_hostname() {
        // "host http" means a host named "http" — do not translate.
        assert_eq!(translate_bpf_filter("host http"), "host http");
        // Dotted hostname stays intact.
        assert_eq!(
            translate_bpf_filter("host http.example.com"),
            "host http.example.com"
        );
    }

    #[test]
    fn host_keyword_then_protocol_elsewhere() {
        // "host 1.2.3.4 and http" — only the second "http" is translated.
        assert_eq!(
            translate_bpf_filter("host 10.0.0.1 and http"),
            "host 10.0.0.1 and tcp port 80"
        );
    }

    #[test]
    fn host_keyword_with_dns_hostname() {
        assert_eq!(
            translate_bpf_filter("host dns.google.com or dns"),
            "host dns.google.com or udp port 53"
        );
    }

    #[test]
    fn multiple_host_keywords() {
        assert_eq!(
            translate_bpf_filter("host ssh-server and host tls.example"),
            "host ssh-server and host tls.example"
        );
    }

    #[test]
    fn protocol_before_host_still_translated() {
        // "tls" before "host" is a protocol, not a hostname.
        assert_eq!(
            translate_bpf_filter("tls and host example.com"),
            "tcp port 443 and host example.com"
        );
    }
}
