use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::models::Packet;
use crate::pipeline::{Pipeline, Producer, RawFrame, StatsSnapshot};
use crate::remote::{spawn_pipe_source, PcapStreamReader, PipeSource, RemoteSpec};
use crate::rotate::{RingBufferOptions, RingWriter};

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

/// Broad class of a capture interface. Network adapters are `Regular`;
/// the special classes cover Linux's usbmon / Bluetooth-HCI / SocketCAN
/// devices and Windows' USBPcap filter devices, so UIs can group and badge
/// hardware-bus capture sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    Regular,
    Loopback,
    Usb,
    Bluetooth,
    Can,
}

impl InterfaceKind {
    /// Stable lowercase tag for serialization ("ethernet", "usb", …).
    pub fn as_str(&self) -> &'static str {
        match self {
            InterfaceKind::Regular => "ethernet",
            InterfaceKind::Loopback => "loopback",
            InterfaceKind::Usb => "usb",
            InterfaceKind::Bluetooth => "bluetooth",
            InterfaceKind::Can => "can",
        }
    }
}

/// Classify a libpcap device by its flags and name.
pub fn interface_kind(dev: &pcap::Device) -> InterfaceKind {
    if dev.flags.is_loopback() {
        return InterfaceKind::Loopback;
    }
    interface_kind_of_name(&dev.name)
}

/// Classify a capture source by name alone. Recognises Linux's `usbmonN`,
/// `bluetoothN` / `bluetooth-monitor`, SocketCAN (`canN`/`vcanN`/`slcanN`)
/// devices and Windows' `\\.\USBPcapN` filter devices.
pub fn interface_kind_of_name(name: &str) -> InterfaceKind {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with(r"\\.\usbpcap") || lower.starts_with("usbmon") {
        return InterfaceKind::Usb;
    }
    if lower.starts_with("bluetooth") {
        return InterfaceKind::Bluetooth;
    }
    let is_num_suffix = |rest: &str| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    for prefix in ["vcan", "slcan", "can"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            if is_num_suffix(rest) {
                return InterfaceKind::Can;
            }
        }
    }
    InterfaceKind::Regular
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

/// Autostop conditions — Wireshark's `-a`: the capture stops itself as soon
/// as **any** configured limit is reached. Counters are shared across every
/// interface of a multi-interface capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopConditions {
    /// Stop after this many seconds of capturing.
    pub duration_secs: Option<u64>,
    /// Stop after this many packets.
    pub packets: Option<u64>,
    /// Stop after this many captured bytes (sum of stored frame sizes).
    pub bytes: Option<u64>,
}

impl StopConditions {
    /// True when no limit is configured (capture runs until stopped).
    pub fn is_unlimited(&self) -> bool {
        self.duration_secs.is_none() && self.packets.is_none() && self.bytes.is_none()
    }
}

/// Runtime side of [`StopConditions`]: lock-free counters shared by all
/// capture threads of one engine run.
struct StopTracker {
    deadline: Option<Instant>,
    max_packets: Option<u64>,
    max_bytes: Option<u64>,
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl StopTracker {
    /// `None` when there is nothing to track — the loops then skip the
    /// per-packet checks entirely.
    fn new(c: &StopConditions) -> Option<Arc<Self>> {
        if c.is_unlimited() {
            return None;
        }
        Some(Arc::new(Self {
            deadline: c
                .duration_secs
                .map(|s| Instant::now() + Duration::from_secs(s)),
            max_packets: c.packets,
            max_bytes: c.bytes,
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }))
    }

    /// Count one captured frame; true once any limit is reached.
    fn record(&self, frame_bytes: u64) -> bool {
        let p = self.packets.fetch_add(1, Ordering::Relaxed) + 1;
        let b = self.bytes.fetch_add(frame_bytes, Ordering::Relaxed) + frame_bytes;
        self.max_packets.is_some_and(|m| p >= m)
            || self.max_bytes.is_some_and(|m| b >= m)
            || self.expired()
    }

    /// Duration check alone — polled on idle read timeouts so a quiet
    /// interface still stops on schedule.
    fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

/// Everything configurable about a capture start, so new options don't keep
/// growing the `start_*` parameter lists.
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// BPF capture filter (friendly protocol names are translated).
    pub bpf_filter: Option<String>,
    /// Write captured packets to this pcap file.
    pub output_path: Option<String>,
    /// Monitor (rfmon) mode for raw 802.11 capture.
    pub monitor: bool,
    /// Autostop limits (duration / packets / bytes).
    pub stop: StopConditions,
    /// Ring-buffer rotation for `output_path` (Wireshark `-b`).
    pub ring: Option<RingBufferOptions>,
}

/// Capture engine built on the parallel pipeline (ROADMAP §2.1): each capture
/// thread feeds raw frames into a lock-free ring, a rayon-backed dissector
/// stage parses them across cores, and finished [`Packet`]s arrive on the
/// `Sender` given to `start_live`/`start_live_multi`/`start_offline`. Capturing
/// on several interfaces at once runs one capture thread + pipeline per
/// interface, all merged onto the one `Sender` (Wireshark-style).
///
/// Beyond local interfaces the engine can also consume *streamed* captures:
/// [`start_remote`](Self::start_remote) (sshdump-style over SSH),
/// [`start_pipe`](Self::start_pipe) (any extcap-style command writing pcap to
/// stdout — USBPcapCMD, ciscodump, custom scripts) and
/// [`start_read_stream`](Self::start_read_stream) (an already-open byte
/// stream, e.g. stdin).
pub struct CaptureEngine {
    running: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
    pipelines: Vec<Pipeline>,
    /// External capture processes (ssh, USBPcapCMD…) killed on stop so a
    /// reader blocked on the pipe wakes up.
    pipes: Vec<PipeSource>,
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
            pipes: Vec::new(),
        }
    }

    /// Back-compat wrapper: single-interface live capture. See
    /// [`start_with`](Self::start_with) for the full-featured entry point.
    pub fn start_live(
        &mut self,
        interface: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
        monitor: bool,
    ) -> Result<()> {
        let opts = CaptureOptions {
            bpf_filter: bpf_filter.map(str::to_string),
            output_path: output_path.map(str::to_string),
            monitor,
            ..Default::default()
        };
        self.start_with(&[interface], &opts, packet_tx)
    }

    /// Back-compat wrapper: multi-interface live capture. See
    /// [`start_with`](Self::start_with) for the full-featured entry point.
    pub fn start_live_multi(
        &mut self,
        interfaces: &[&str],
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
        monitor: bool,
    ) -> Result<()> {
        let opts = CaptureOptions {
            bpf_filter: bpf_filter.map(str::to_string),
            output_path: output_path.map(str::to_string),
            monitor,
            ..Default::default()
        };
        self.start_with(interfaces, &opts, packet_tx)
    }

    /// Live capture on one or several interfaces with the full option set:
    /// BPF filter, save-to-file (with optional ring-buffer rotation) and
    /// autostop conditions. Each interface gets its own capture thread and
    /// dissector pipeline, so mixed link types (Ethernet + Wi-Fi) are each
    /// dissected correctly; interfaces that fail to open are skipped with a
    /// warning, and it's an error only if *none* opens.
    ///
    /// Writing to a file while capturing on multiple interfaces is not
    /// supported — classic pcap has one global link type — so the output
    /// path is ignored (with a warning) for >1 interface.
    pub fn start_with(
        &mut self,
        interfaces: &[&str],
        opts: &CaptureOptions,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        if interfaces.is_empty() {
            anyhow::bail!("No capture interface specified.");
        }

        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        // Open every interface up front. Keep the ones that open; collect the
        // rest as warnings so one dead adapter doesn't sink the whole capture.
        let mut opened = Vec::new();
        let mut errors = Vec::new();
        for &iface in interfaces {
            match open_live_capture(iface, opts.bpf_filter.as_deref(), opts.monitor) {
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

        // File writing (plain or ring-buffer) only works for one interface.
        let multi = opened.len() > 1;
        let mut writer = match build_file_writer(opts, opened[0].2, multi) {
            Ok(w) => w,
            Err(e) => {
                running.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };

        // One autostop tracker shared by every capture thread.
        let tracker = StopTracker::new(&opts.stop);

        for (iface, cap, linktype) in opened {
            let tx = packet_tx.clone();
            let pipeline = Pipeline::start(linktype, tx, running.clone());
            let producer = pipeline.producer();
            let run = running.clone();
            let trk = tracker.clone();
            let wtr = writer.take(); // only the first interface writes
            let handle = thread::Builder::new()
                .name(format!("capture:{iface}"))
                .spawn(move || capture_loop(cap, &iface, producer, run, trk, wtr))
                .context("Failed to spawn capture thread")?;
            self.handles.push(handle);
            self.pipelines.push(pipeline);
        }
        Ok(())
    }

    /// Capture from a remote host over SSH, sshdump-style: runs
    /// `tcpdump -U -w -` (or [`RemoteSpec::remote_command`]) on the remote
    /// side and dissects the pcap stream it sends back. Blocks until the
    /// stream header arrives, so connection and authentication errors
    /// surface here with the SSH client's message attached.
    pub fn start_remote(
        &mut self,
        spec: &RemoteSpec,
        opts: &CaptureOptions,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let (program, args) = spec.command();
        self.start_pipe(&program, &args, &spec.describe(), opts, packet_tx)
    }

    /// Capture from any local command that writes a pcap/pcapng stream to
    /// its stdout — the extcap model. This is how Windows USB capture runs
    /// (`USBPcapCMD.exe -d \\.\USBPcap1 -o -`) and how tools like ciscodump
    /// or androiddump can be plugged in without netscope knowing them.
    ///
    /// `opts.bpf_filter` is ignored (filtering happens in the producing
    /// command); output/ring and autostop options apply normally.
    pub fn start_pipe(
        &mut self,
        program: &str,
        args: &[String],
        label: &str,
        opts: &CaptureOptions,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let mut pipe = match spawn_pipe_source(program, args, label) {
            Ok(p) => p,
            Err(e) => {
                running.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        let stdout = pipe
            .take_stdout()
            .context("capture command has no stdout pipe")?;

        // Blocks until the pcap header arrives — this is where a failed SSH
        // login or a mistyped remote command comes back to the caller.
        let reader = match PcapStreamReader::new(stdout) {
            Ok(r) => r,
            Err(e) => {
                pipe.kill();
                running.store(false, Ordering::SeqCst);
                let stderr = pipe.stderr_excerpt();
                if stderr.is_empty() {
                    return Err(e.context(format!("'{label}' produced no capture stream")));
                }
                return Err(e.context(format!(
                    "'{label}' produced no capture stream. The command reported:\n  {stderr}"
                )));
            }
        };

        let kill_child = pipe.child.clone();
        self.pipes.push(pipe);
        self.spawn_stream_thread(reader, label, opts, packet_tx, move || {
            if let Ok(mut child) = kill_child.lock() {
                let _ = child.kill();
                let _ = child.wait();
            }
        })
    }

    /// Dissect a pcap/pcapng stream from an already-open byte source —
    /// netscope's `-i -` (read a live capture from stdin, e.g.
    /// `ssh host "tcpdump -U -w -" | netscope -i -`).
    pub fn start_read_stream(
        &mut self,
        source: Box<dyn Read + Send>,
        label: &str,
        opts: &CaptureOptions,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);
        let reader = match PcapStreamReader::new(source) {
            Ok(r) => r,
            Err(e) => {
                running.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        self.spawn_stream_thread(reader, label, opts, packet_tx, || {})
    }

    /// Shared tail of the stream-based starts: pipeline + reader thread.
    /// `on_exit` runs when the stream ends (used to reap a child process).
    fn spawn_stream_thread<R: Read + Send + 'static>(
        &mut self,
        mut reader: PcapStreamReader<R>,
        label: &str,
        opts: &CaptureOptions,
        packet_tx: Sender<Packet>,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let running = self.running.clone();
        let linktype = reader.linktype();
        let mut writer = match build_file_writer(opts, linktype, false) {
            Ok(w) => w,
            Err(e) => {
                running.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        let tracker = StopTracker::new(&opts.stop);

        let pipeline = Pipeline::start(linktype, packet_tx, running.clone());
        let producer = pipeline.producer();
        let run = running.clone();
        let label = label.to_string();
        let handle = thread::Builder::new()
            .name(format!("stream:{label}"))
            .spawn(move || {
                while run.load(Ordering::SeqCst) {
                    match reader.next_frame() {
                        Ok(Some(frame)) => {
                            let mut write_failed = false;
                            if let Some(w) = writer.as_mut() {
                                if let Err(e) = w.write(
                                    frame.ts_sec as u32,
                                    frame.ts_nanos / 1000,
                                    frame.orig_len,
                                    &frame.data,
                                ) {
                                    eprintln!("Warning: capture file write failed: {e} — file saving disabled");
                                    write_failed = true;
                                }
                            }
                            if write_failed {
                                writer = None;
                            }
                            let hit = tracker
                                .as_deref()
                                .is_some_and(|t| t.record(frame.data.len() as u64));
                            producer.push_live(frame);
                            if hit {
                                break;
                            }
                        }
                        Ok(None) => break, // clean end of stream
                        Err(e) => {
                            // A killed child (user stop) also lands here —
                            // only report when the capture was still running.
                            if run.load(Ordering::SeqCst) {
                                eprintln!("Capture stream '{label}' ended: {e:#}");
                            }
                            break;
                        }
                    }
                }
                if let Some(w) = writer {
                    if let Err(e) = w.finish() {
                        eprintln!("Warning: capture file flush failed: {e}");
                    }
                }
                // One stream is the whole capture: mark the engine stopped and
                // reap the producing process so nothing lingers.
                run.store(false, Ordering::SeqCst);
                on_exit();
                producer.finish();
            })
            .context("Failed to spawn capture stream thread")?;

        self.handles.push(handle);
        self.pipelines.push(pipeline);
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

        // Detect format (ROADMAP §2.2 / §2.5 support for other formats)
        let format = crate::formats::detect(filepath).ok();
        let is_native = format.is_some_and(|f| f.is_native_pcap());

        if is_native {
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
        } else {
            let mut reader = crate::formats::RecordReader::open(filepath)?;
            let linktype = reader.linktype();
            let output_path = output_path.map(|s| s.to_string());

            let pipeline = Pipeline::start(linktype, packet_tx, running.clone());
            let producer = pipeline.producer();

            let handle = thread::Builder::new()
                .name("capture".into())
                .spawn(move || {
                    let mut writer = output_path.as_ref().and_then(|path| {
                        match RingWriter::create(path, linktype, RingBufferOptions::default()) {
                            Ok(w) => Some(w),
                            Err(e) => {
                                eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
                                None
                            }
                        }
                    });

                    while running.load(Ordering::SeqCst) {
                        match reader.next_frame() {
                            Ok(Some(frame)) => {
                                if let Some(ref mut w) = writer {
                                    let _ = w.write(
                                        frame.ts_sec as u32,
                                        frame.ts_nanos / 1000,
                                        frame.orig_len,
                                        &frame.data,
                                    );
                                }
                                if !producer.push_blocking(frame, &running) {
                                    break;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                eprintln!("Capture error: {e}");
                                break;
                            }
                        }
                    }
                    if let Some(w) = writer {
                        let _ = w.finish();
                    }
                    producer.finish();
                })
                .context("Failed to spawn capture thread")?;

            self.handles.push(handle);
            self.pipelines.push(pipeline);
            Ok(())
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Kill external capture processes first: a stream reader blocked on
        // its pipe only wakes up when the writing side goes away.
        for pipe in self.pipes.drain(..) {
            pipe.kill();
        }
        // Join every capture thread so all producers have declared their
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

/// The live-capture wire loop: read packets until stopped, feed the
/// pipeline, optionally write the capture file and check autostop limits.
fn capture_loop(
    mut cap: pcap::Capture<pcap::Active>,
    iface: &str,
    producer: Producer,
    running: Arc<AtomicBool>,
    tracker: Option<Arc<StopTracker>>,
    mut writer: Option<RingWriter>,
) {
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(pkt) => {
                let mut write_failed = false;
                if let Some(w) = writer.as_mut() {
                    // tv_sec is i32 on Windows but i64 on Linux/macOS.
                    #[allow(clippy::unnecessary_cast)]
                    let ts_sec = pkt.header.ts.tv_sec as u32;
                    if let Err(e) =
                        w.write(ts_sec, pkt.header.ts.tv_usec as u32, pkt.header.len, pkt.data)
                    {
                        eprintln!(
                            "Warning: capture file write failed: {e} — file saving disabled"
                        );
                        write_failed = true;
                    }
                }
                if write_failed {
                    writer = None;
                }
                let hit = tracker
                    .as_deref()
                    .is_some_and(|t| t.record(pkt.header.caplen as u64));
                // Live capture must never stall the wire loop: a full ring
                // drops the frame (counted in stats).
                producer.push_live(raw_frame(pkt));
                if hit {
                    // Autostop limit reached — stops every sibling thread too.
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Idle tick: a duration limit must fire on quiet interfaces.
                if tracker.as_deref().is_some_and(|t| t.expired()) {
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                eprintln!("Capture error on '{iface}': {e}");
                break;
            }
        }
    }
    if let Some(w) = writer {
        if let Err(e) = w.finish() {
            eprintln!("Warning: capture file flush failed: {e}");
        }
    }
    producer.finish();
}

/// Build the capture-file writer for a live/stream capture. `None` when no
/// output was requested (a ring-buffer config without an output file is an
/// error — there would be nothing to rotate).
fn build_file_writer(
    opts: &CaptureOptions,
    linktype: i32,
    multi_interface: bool,
) -> Result<Option<RingWriter>> {
    let Some(path) = opts.output_path.as_deref() else {
        if opts.ring.is_some() {
            anyhow::bail!(
                "a ring buffer needs an output file to write to (add -w / an output path)"
            );
        }
        return Ok(None);
    };
    if multi_interface {
        eprintln!(
            "Warning: saving to a file isn't supported when capturing on multiple interfaces — the capture will not be written to disk."
        );
        return Ok(None);
    }
    let writer = RingWriter::create(path, linktype, opts.ring.unwrap_or_default())
        .with_context(|| format!("cannot create capture file '{path}'"))?;
    Ok(Some(writer))
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
    use crate::dissectors::test_helpers::build_tcp_packet;

    /// In-memory little-endian classic pcap with `n` HTTP frames.
    fn test_pcap_bytes(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
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
        buf
    }

    #[test]
    fn read_stream_delivers_packets_and_marks_engine_stopped() {
        let mut eng = CaptureEngine::new();
        let (tx, rx) = crossbeam_channel::unbounded();
        let stream = std::io::Cursor::new(test_pcap_bytes(5));
        eng.start_read_stream(Box::new(stream), "test", &CaptureOptions::default(), tx)
            .unwrap();
        let packets: Vec<Packet> = rx.iter().collect(); // ends when pipeline closes tx
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].protocol, crate::models::Protocol::Http);
        assert!(!eng.is_running(), "stream end must mark the engine stopped");
        eng.stop();
        let stats = eng.pipeline_stats().unwrap();
        assert_eq!(stats.dissected, 5);
    }

    #[test]
    fn autostop_packet_limit_cuts_the_stream() {
        let mut eng = CaptureEngine::new();
        let (tx, rx) = crossbeam_channel::unbounded();
        let opts = CaptureOptions {
            stop: StopConditions {
                packets: Some(3),
                ..Default::default()
            },
            ..Default::default()
        };
        let stream = std::io::Cursor::new(test_pcap_bytes(10));
        eng.start_read_stream(Box::new(stream), "test", &opts, tx)
            .unwrap();
        let packets: Vec<Packet> = rx.iter().collect();
        assert_eq!(packets.len(), 3, "must stop exactly at the packet limit");
        assert!(!eng.is_running());
    }

    #[test]
    fn autostop_byte_limit_cuts_the_stream() {
        let mut eng = CaptureEngine::new();
        let (tx, rx) = crossbeam_channel::unbounded();
        let opts = CaptureOptions {
            stop: StopConditions {
                bytes: Some(1), // first frame already exceeds this
                ..Default::default()
            },
            ..Default::default()
        };
        let stream = std::io::Cursor::new(test_pcap_bytes(10));
        eng.start_read_stream(Box::new(stream), "test", &opts, tx)
            .unwrap();
        let packets: Vec<Packet> = rx.iter().collect();
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn stream_capture_writes_output_file() {
        let dir = std::env::temp_dir().join(format!(
            "netscope-stream-save-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("saved.pcap");

        let mut eng = CaptureEngine::new();
        let (tx, rx) = crossbeam_channel::unbounded();
        let opts = CaptureOptions {
            output_path: Some(out.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let stream = std::io::Cursor::new(test_pcap_bytes(4));
        eng.start_read_stream(Box::new(stream), "test", &opts, tx)
            .unwrap();
        let n = rx.iter().count();
        eng.stop();
        assert_eq!(n, 4);

        // The saved file must itself be a readable capture with 4 packets.
        let saved = std::fs::read(&out).unwrap();
        assert_eq!(&saved[0..4], &0xa1b2c3d4u32.to_le_bytes());
        let reader = crate::remote::PcapStreamReader::new(saved.as_slice());
        let mut reader = reader.unwrap();
        let mut count = 0;
        while reader.next_frame().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 4);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ring_buffer_without_output_path_is_rejected() {
        let mut eng = CaptureEngine::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let opts = CaptureOptions {
            ring: Some(RingBufferOptions {
                filesize_kb: Some(100),
                ..Default::default()
            }),
            ..Default::default()
        };
        let stream = std::io::Cursor::new(test_pcap_bytes(1));
        let err = eng
            .start_read_stream(Box::new(stream), "test", &opts, tx)
            .unwrap_err();
        assert!(err.to_string().contains("output file"), "{err}");
        assert!(!eng.is_running());
    }

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
