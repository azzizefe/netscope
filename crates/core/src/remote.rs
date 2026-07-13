//! Remote & external capture sources — netscope's take on Wireshark's
//! sshdump / extcap family.
//!
//! The building block is [`PcapStreamReader`]: an incremental parser that
//! turns any live byte stream (a pipe, stdin, a socket) speaking classic
//! pcap **or** pcapng into [`RawFrame`]s. On top of it:
//!
//! * [`RemoteSpec`] builds an `ssh host "tcpdump -U -w -"` command line —
//!   the exact mechanism sshdump uses. Works against anything with an SSH
//!   server and tcpdump/dumpcap (Linux boxes, routers, Raspberry Pis).
//! * [`spawn_pipe_source`] runs **any** local command whose stdout is a
//!   capture stream (extcap-style): `ciscodump`, `androiddump`, Windows'
//!   `USBPcapCMD.exe`, or a custom script.
//! * The USBPcap helpers locate `USBPcapCMD.exe` on Windows and enumerate
//!   its root-hub capture devices, so USB capture plugs into the same pipe.
//!
//! SSH authentication is key/agent-based (`BatchMode=yes`): a GUI process
//! has no terminal to answer password prompts on, so we fail fast with the
//! server's message instead of hanging forever.

use std::collections::VecDeque;
use std::io::{self, BufRead, Read};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::pipeline::RawFrame;

// ---- Streaming pcap/pcapng parser -------------------------------------------

/// Magic numbers for the classic pcap global header (see `stream.rs`).
const MAGIC_US: u32 = 0xa1b2_c3d4;
const MAGIC_NS: u32 = 0xa1b2_3c4d;
const MAGIC_US_SWAPPED: u32 = 0xd4c3_b2a1;
const MAGIC_NS_SWAPPED: u32 = 0x4d3c_b2a1;

/// pcapng block types.
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_PACKET_OBSOLETE: u32 = 0x0000_0002;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_EPB: u32 = 0x0000_0006;
const OPT_IF_TSRESOL: u16 = 0x0009;

/// Longer records/blocks are treated as stream corruption, not data.
const MAX_SANE_LEN: u32 = 64 * 1024 * 1024;

/// Default pcapng timestamp resolution: microseconds.
const DEFAULT_TPS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
enum Format {
    Pcap { swapped: bool, nanos: bool },
    PcapNg { swapped: bool },
}

/// Incremental pcap/pcapng parser over any [`Read`] source. The constructor
/// blocks until the stream header (and, for pcapng, the first interface
/// block) arrives, so the link type is known before the first frame.
pub struct PcapStreamReader<R: Read> {
    src: R,
    format: Format,
    linktype: i32,
    /// pcapng: timestamp ticks-per-second for each interface, in IDB order.
    if_tps: Vec<u64>,
}

impl<R: Read> PcapStreamReader<R> {
    /// Read the stream header and prepare to yield frames. Fails on a byte
    /// stream that isn't pcap or pcapng (with a hint about what arrived).
    pub fn new(mut src: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        src.read_exact(&mut magic)
            .context("capture stream ended before a pcap header arrived")?;
        match u32::from_le_bytes(magic) {
            m @ (MAGIC_US | MAGIC_NS | MAGIC_US_SWAPPED | MAGIC_NS_SWAPPED) => {
                let (swapped, nanos) = match m {
                    MAGIC_US => (false, false),
                    MAGIC_NS => (false, true),
                    MAGIC_US_SWAPPED => (true, false),
                    _ => (true, true),
                };
                let mut rest = [0u8; 20];
                src.read_exact(&mut rest)
                    .context("capture stream ended inside the pcap global header")?;
                let linktype = read_u32(&rest[16..20], swapped) as i32;
                Ok(Self {
                    src,
                    format: Format::Pcap { swapped, nanos },
                    linktype,
                    if_tps: Vec::new(),
                })
            }
            PCAPNG_SHB => {
                let mut reader = Self {
                    src,
                    format: Format::PcapNg { swapped: false },
                    linktype: -1,
                    if_tps: Vec::new(),
                };
                reader.read_shb_body()?;
                // The spec puts every IDB before the packets that use it, so
                // reading up to the first IDB can't skip any packet block.
                while reader.if_tps.is_empty() {
                    let Some((block_type, body)) = reader.read_block()? else {
                        anyhow::bail!("pcapng stream ended before an interface description block");
                    };
                    if block_type == BLOCK_IDB {
                        reader.parse_idb(&body);
                    }
                }
                Ok(reader)
            }
            other => anyhow::bail!(
                "not a pcap/pcapng stream (first bytes 0x{other:08x}) — the remote command must \
                 write a capture to stdout, e.g. `tcpdump -U -w -`"
            ),
        }
    }

    /// The capture's link-layer type (first interface's for pcapng).
    pub fn linktype(&self) -> i32 {
        self.linktype
    }

    /// Next frame, `Ok(None)` on a clean end of stream. A stream cut mid
    /// record surfaces as an error so callers can report it.
    pub fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        match self.format {
            Format::Pcap { swapped, nanos } => self.next_pcap_frame(swapped, nanos),
            Format::PcapNg { .. } => self.next_pcapng_frame(),
        }
    }

    fn next_pcap_frame(&mut self, swapped: bool, nanos: bool) -> Result<Option<RawFrame>> {
        let mut hdr = [0u8; 16];
        if !read_full_or_eof(&mut self.src, &mut hdr)? {
            return Ok(None);
        }
        let ts_sec = read_u32(&hdr[0..4], swapped);
        let ts_frac = read_u32(&hdr[4..8], swapped);
        let caplen = read_u32(&hdr[8..12], swapped);
        let orig_len = read_u32(&hdr[12..16], swapped);
        if caplen > MAX_SANE_LEN {
            anyhow::bail!("corrupt pcap stream: record claims {caplen} bytes");
        }
        let mut data = vec![0u8; caplen as usize];
        self.src
            .read_exact(&mut data)
            .context("capture stream ended mid-record")?;
        Ok(Some(RawFrame {
            ts_sec: ts_sec as i64,
            ts_nanos: if nanos { ts_frac } else { ts_frac.saturating_mul(1000) },
            orig_len,
            data,
        }))
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<RawFrame>> {
        loop {
            let Some((block_type, body)) = self.read_block()? else {
                return Ok(None);
            };
            match block_type {
                BLOCK_EPB => {
                    if body.len() < 20 {
                        continue; // malformed; skip rather than kill the stream
                    }
                    let swapped = self.swapped();
                    let iface = read_u32(&body[0..4], swapped) as usize;
                    let ts_high = read_u32(&body[4..8], swapped) as u64;
                    let ts_low = read_u32(&body[8..12], swapped) as u64;
                    let caplen = read_u32(&body[12..16], swapped) as usize;
                    let orig_len = read_u32(&body[16..20], swapped);
                    if body.len() < 20 + caplen {
                        continue;
                    }
                    let ts = (ts_high << 32) | ts_low;
                    let tps = self.if_tps.get(iface).copied().unwrap_or(DEFAULT_TPS);
                    let (ts_sec, ts_nanos) = split_timestamp(ts, tps);
                    return Ok(Some(RawFrame {
                        ts_sec,
                        ts_nanos,
                        orig_len,
                        data: body[20..20 + caplen].to_vec(),
                    }));
                }
                BLOCK_SPB => {
                    if body.len() < 4 {
                        continue;
                    }
                    let orig_len = read_u32(&body[0..4], self.swapped());
                    let caplen = (body.len() - 4).min(orig_len as usize);
                    return Ok(Some(RawFrame {
                        ts_sec: 0,
                        ts_nanos: 0,
                        orig_len,
                        data: body[4..4 + caplen].to_vec(),
                    }));
                }
                BLOCK_PACKET_OBSOLETE => {
                    // Legacy Packet Block: iface u16, drops u16, then EPB-like.
                    if body.len() < 20 {
                        continue;
                    }
                    let swapped = self.swapped();
                    let iface = read_u16(&body[0..2], swapped) as usize;
                    let ts_high = read_u32(&body[4..8], swapped) as u64;
                    let ts_low = read_u32(&body[8..12], swapped) as u64;
                    let caplen = read_u32(&body[12..16], swapped) as usize;
                    let orig_len = read_u32(&body[16..20], swapped);
                    if body.len() < 20 + caplen {
                        continue;
                    }
                    let tps = self.if_tps.get(iface).copied().unwrap_or(DEFAULT_TPS);
                    let (ts_sec, ts_nanos) = split_timestamp((ts_high << 32) | ts_low, tps);
                    return Ok(Some(RawFrame {
                        ts_sec,
                        ts_nanos,
                        orig_len,
                        data: body[20..20 + caplen].to_vec(),
                    }));
                }
                BLOCK_IDB => self.parse_idb(&body),
                PCAPNG_SHB => {
                    // A new section restarts endianness and the interface list.
                    self.parse_shb_from_body(&body)?;
                }
                _ => {} // statistics, name resolution, … — not packets
            }
        }
    }

    fn swapped(&self) -> bool {
        match self.format {
            Format::PcapNg { swapped } => swapped,
            Format::Pcap { swapped, .. } => swapped,
        }
    }

    /// Read one pcapng block after the 4-byte type: `(type, body)` where the
    /// body excludes the trailing total-length word. `None` on clean EOF.
    fn read_block(&mut self) -> Result<Option<(u32, Vec<u8>)>> {
        let mut head = [0u8; 8];
        if !read_full_or_eof(&mut self.src, &mut head)? {
            return Ok(None);
        }
        let block_type = read_u32(&head[0..4], self.swapped());
        // A Section Header Block's length field may use the *new* section's
        // endianness — its byte-order magic sits in the body, so read the
        // length both ways and pick the sane one.
        let total_len = if block_type == PCAPNG_SHB {
            let le = u32::from_le_bytes(head[4..8].try_into().unwrap());
            let be = u32::from_be_bytes(head[4..8].try_into().unwrap());
            if (12..=MAX_SANE_LEN).contains(&le) && le % 4 == 0 {
                le
            } else {
                be
            }
        } else {
            read_u32(&head[4..8], self.swapped())
        };
        if !(12..=MAX_SANE_LEN).contains(&total_len) || !total_len.is_multiple_of(4) {
            anyhow::bail!("corrupt pcapng stream: block length {total_len}");
        }
        let mut rest = vec![0u8; total_len as usize - 8];
        self.src
            .read_exact(&mut rest)
            .context("capture stream ended mid-block")?;
        rest.truncate(rest.len() - 4); // drop the trailing total-length copy
        Ok(Some((block_type, rest)))
    }

    /// Parse a Section Header Block body already read from the stream:
    /// fixes endianness for the section and clears the interface table.
    fn parse_shb_from_body(&mut self, body: &[u8]) -> Result<()> {
        if body.len() < 4 {
            anyhow::bail!("pcapng section header too short");
        }
        let bom = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let swapped = match bom {
            PCAPNG_BYTE_ORDER => false,
            b if b == PCAPNG_BYTE_ORDER.swap_bytes() => true,
            other => anyhow::bail!("pcapng byte-order magic invalid (0x{other:08x})"),
        };
        self.format = Format::PcapNg { swapped };
        self.if_tps.clear();
        Ok(())
    }

    /// Consume the SHB right after its 4-byte type (constructor path).
    fn read_shb_body(&mut self) -> Result<()> {
        let mut head = [0u8; 8]; // total length + byte-order magic
        self.src
            .read_exact(&mut head)
            .context("capture stream ended inside the pcapng section header")?;
        let bom = u32::from_le_bytes(head[4..8].try_into().unwrap());
        let swapped = match bom {
            PCAPNG_BYTE_ORDER => false,
            b if b == PCAPNG_BYTE_ORDER.swap_bytes() => true,
            other => anyhow::bail!("pcapng byte-order magic invalid (0x{other:08x})"),
        };
        self.format = Format::PcapNg { swapped };
        let total_len = read_u32(&head[0..4], swapped);
        if !(12..=MAX_SANE_LEN).contains(&total_len) || !total_len.is_multiple_of(4) {
            anyhow::bail!("corrupt pcapng stream: section header length {total_len}");
        }
        skip_bytes(&mut self.src, total_len as u64 - 12)
            .context("capture stream ended inside the pcapng section header")?;
        Ok(())
    }

    /// Interface Description Block: link type + timestamp resolution.
    fn parse_idb(&mut self, body: &[u8]) {
        if body.len() < 8 {
            self.if_tps.push(DEFAULT_TPS);
            return;
        }
        let swapped = self.swapped();
        let linktype = read_u16(&body[0..2], swapped) as i32;
        if self.linktype < 0 {
            self.linktype = linktype;
        }
        // Options follow the 8 fixed bytes: code u16, len u16, value padded
        // to 4-byte alignment; code 0 ends the list.
        let mut tps = DEFAULT_TPS;
        let mut off = 8;
        while off + 4 <= body.len() {
            let code = read_u16(&body[off..off + 2], swapped);
            let olen = read_u16(&body[off + 2..off + 4], swapped) as usize;
            off += 4;
            if code == 0 {
                break;
            }
            if off + olen > body.len() {
                break;
            }
            if code == OPT_IF_TSRESOL && olen >= 1 {
                tps = tsresol_to_tps(body[off]);
            }
            off += olen + ((4 - olen % 4) % 4);
        }
        self.if_tps.push(tps);
    }
}

/// `if_tsresol` byte → timestamp ticks per second. MSB set means a power of
/// two, clear means a power of ten; out-of-range exponents fall back to the
/// microsecond default rather than overflowing.
fn tsresol_to_tps(v: u8) -> u64 {
    if v & 0x80 != 0 {
        let exp = v & 0x7f;
        if exp < 64 {
            1u64 << exp
        } else {
            DEFAULT_TPS
        }
    } else if v < 20 {
        10u64.pow(v as u32)
    } else {
        DEFAULT_TPS
    }
}

/// A tick count at `tps` ticks/second → (seconds, nanoseconds).
fn split_timestamp(ts: u64, tps: u64) -> (i64, u32) {
    let tps = tps.max(1);
    let secs = (ts / tps) as i64;
    let frac = ts % tps;
    let nanos = (frac as u128 * 1_000_000_000 / tps as u128) as u32;
    (secs, nanos)
}

fn read_u32(b: &[u8], swapped: bool) -> u32 {
    let raw = [b[0], b[1], b[2], b[3]];
    if swapped {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

fn read_u16(b: &[u8], swapped: bool) -> u16 {
    let raw = [b[0], b[1]];
    if swapped {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    }
}

/// Fill `buf` completely. `Ok(false)` when the stream ends *before the first
/// byte* (clean EOF at a record boundary); an end mid-buffer is an error.
fn read_full_or_eof<R: Read>(src: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream ended mid-record",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Discard `n` bytes from a non-seekable stream.
fn skip_bytes<R: Read>(src: &mut R, mut n: u64) -> io::Result<()> {
    let mut scratch = [0u8; 4096];
    while n > 0 {
        let take = scratch.len().min(n as usize);
        src.read_exact(&mut scratch[..take])?;
        n -= take as u64;
    }
    Ok(())
}

// ---- SSH remote capture (sshdump-style) --------------------------------------

/// How to reach a remote capture source over SSH. The default remote command
/// is `tcpdump -U -n -i <interface> -s 0 -w -` (packet-buffered pcap on
/// stdout); `remote_command` overrides it entirely for hosts with dumpcap,
/// tshark or a vendor CLI instead.
#[derive(Debug, Clone, Default)]
pub struct RemoteSpec {
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Private-key file passed to `ssh -i`.
    pub identity_file: Option<String>,
    /// Remote interface (default "any" — Linux cooked capture).
    pub interface: Option<String>,
    /// Remote BPF capture filter (protocol names translated like local ones).
    pub capture_filter: Option<String>,
    /// Full remote command override; when set, interface/filter/sudo are the
    /// caller's responsibility.
    pub remote_command: Option<String>,
    /// Prefix the remote capture command with `sudo` (passwordless sudo on
    /// the remote side, the standard sshdump setup).
    pub use_sudo: bool,
}

impl RemoteSpec {
    /// The local command to run: `("ssh", args…)`. Uses `BatchMode=yes` so a
    /// key/agent-less host fails immediately instead of prompting a GUI
    /// process that has no terminal.
    pub fn command(&self) -> (String, Vec<String>) {
        let mut args: Vec<String> = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            // No pty: a terminal would mangle the binary pcap stream.
            "-T".into(),
        ];
        if let Some(port) = self.port {
            args.push("-p".into());
            args.push(port.to_string());
        }
        if let Some(id) = &self.identity_file {
            args.push("-i".into());
            args.push(id.clone());
        }
        args.push(match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        });
        args.push(self.remote_shell_command());
        ("ssh".into(), args)
    }

    /// The command executed on the remote host.
    pub fn remote_shell_command(&self) -> String {
        if let Some(cmd) = &self.remote_command {
            return cmd.clone();
        }
        let sudo = if self.use_sudo { "sudo " } else { "" };
        let iface = self.interface.as_deref().unwrap_or("any");
        let mut cmd = format!("{sudo}tcpdump -U -n -i {} -s 0 -w -", shell_quote(iface));
        if let Some(filter) = &self.capture_filter {
            let translated = crate::capture::translate_bpf_filter(filter);
            cmd.push(' ');
            cmd.push_str(&shell_quote(&translated));
        }
        cmd
    }

    /// Short label for threads and log lines, e.g. `admin@10.0.0.5:eth0`.
    pub fn describe(&self) -> String {
        let iface = self.interface.as_deref().unwrap_or("any");
        match &self.user {
            Some(u) => format!("{u}@{}:{iface}", self.host),
            None => format!("{}:{iface}", self.host),
        }
    }
}

/// Single-quote a string for a POSIX remote shell (embedded quotes escaped).
fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

// ---- External command sources (extcap-style) ---------------------------------

/// A spawned capture command: its stdout is the pcap stream, stderr is
/// drained to our stderr (tail kept for error messages), and the child
/// handle lets the engine kill it on stop.
pub struct PipeSource {
    pub child: Arc<Mutex<Child>>,
    stdout: Option<ChildStdout>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
}

impl PipeSource {
    /// The capture stream (present until taken once).
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// The last few stderr lines the command printed — the actual reason
    /// behind most "stream ended" failures (auth errors, tcpdump usage…).
    pub fn stderr_excerpt(&self) -> String {
        let tail = self.stderr_tail.lock().map(|t| t.clone()).unwrap_or_default();
        tail.iter().cloned().collect::<Vec<_>>().join("\n  ")
    }

    /// Kill the child (used on stop; unblocks a reader stuck on the pipe).
    pub fn kill(&self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn `program args…` with stdout piped as a capture stream. `label`
/// prefixes forwarded stderr lines so multi-source sessions stay readable.
pub fn spawn_pipe_source(program: &str, args: &[String], label: &str) -> Result<PipeSource> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run '{program}' — is it installed and on PATH?"))?;

    let stdout = child
        .stdout
        .take()
        .context("child process has no stdout pipe")?;
    let stderr = child.stderr.take();

    let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(8)));
    if let Some(stderr) = stderr {
        let tail = stderr_tail.clone();
        let label = label.to_string();
        std::thread::Builder::new()
            .name(format!("stderr:{label}"))
            .spawn(move || {
                for line in io::BufReader::new(stderr).lines().map_while(|l| l.ok()) {
                    if line.trim().is_empty() {
                        continue;
                    }
                    eprintln!("[{label}] {line}");
                    if let Ok(mut t) = tail.lock() {
                        if t.len() >= 8 {
                            t.pop_front();
                        }
                        t.push_back(line);
                    }
                }
            })
            .ok();
    }

    Ok(PipeSource {
        child: Arc::new(Mutex::new(child)),
        stdout: Some(stdout),
        stderr_tail,
    })
}

// ---- USBPcap (Windows USB capture) --------------------------------------------

/// Where USBPcap's command-line capture tool lives, when installed.
#[cfg(windows)]
pub fn usbpcap_cmd_path() -> Option<std::path::PathBuf> {
    let bases = [
        std::env::var_os("ProgramFiles").map(std::path::PathBuf::from),
        Some(std::path::PathBuf::from(r"C:\Program Files")),
        Some(std::path::PathBuf::from(r"C:\Program Files (x86)")),
    ];
    bases
        .into_iter()
        .flatten()
        .map(|b| b.join("USBPcap").join("USBPcapCMD.exe"))
        .find(|p| p.exists())
}

#[cfg(not(windows))]
pub fn usbpcap_cmd_path() -> Option<std::path::PathBuf> {
    None
}

/// USBPcap root-hub capture devices as `(device, display)` pairs, e.g.
/// `("\\.\USBPcap1", "USBPcap1: …")`. Empty when USBPcap isn't installed
/// (on Linux, usbmon interfaces appear in the normal interface list instead).
pub fn usbpcap_interfaces() -> Vec<(String, String)> {
    let Some(cmd) = usbpcap_cmd_path() else {
        return Vec::new();
    };
    let Ok(out) = Command::new(&cmd).arg("--extcap-interfaces").output() else {
        return Vec::new();
    };
    parse_extcap_interfaces(&String::from_utf8_lossy(&out.stdout))
}

/// Parse extcap `--extcap-interfaces` output:
/// `interface {value=\\.\USBPcap1}{display=USBPcap1}` → (value, display).
fn parse_extcap_interfaces(text: &str) -> Vec<(String, String)> {
    let field = |line: &str, key: &str| -> Option<String> {
        let start = line.find(&format!("{{{key}="))? + key.len() + 2;
        let end = line[start..].find('}')? + start;
        Some(line[start..end].to_string())
    };
    text.lines()
        .filter(|l| l.trim_start().starts_with("interface "))
        .filter_map(|l| {
            let value = field(l, "value")?;
            let display = field(l, "display").unwrap_or_else(|| value.clone());
            Some((value, display))
        })
        .collect()
}

/// The local command that streams a USBPcap device to stdout, ready for
/// [`spawn_pipe_source`]. `-A` captures from every device on the root hub
/// (skipping the interactive device picker).
pub fn usbpcap_capture_command(device: &str) -> Result<(String, Vec<String>)> {
    let cmd = usbpcap_cmd_path().context(
        "USBPcap is not installed — get it from https://desowin.org/usbpcap (Windows only)",
    )?;
    Ok((
        cmd.to_string_lossy().into_owned(),
        vec![
            "-d".into(),
            device.into(),
            "-o".into(),
            "-".into(),
            "-A".into(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- classic pcap streaming ----

    fn pcap_header(magic: u32, be: bool, linktype: u32) -> Vec<u8> {
        let mut v = Vec::new();
        let w32 = |v: &mut Vec<u8>, x: u32| {
            v.extend_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() })
        };
        let w16 = |v: &mut Vec<u8>, x: u16| {
            v.extend_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() })
        };
        w32(&mut v, magic);
        w16(&mut v, 2);
        w16(&mut v, 4);
        w32(&mut v, 0);
        w32(&mut v, 0);
        w32(&mut v, 65535);
        w32(&mut v, linktype);
        v
    }

    fn pcap_record(be: bool, ts_sec: u32, ts_frac: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let w32 = |v: &mut Vec<u8>, x: u32| {
            v.extend_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() })
        };
        w32(&mut v, ts_sec);
        w32(&mut v, ts_frac);
        w32(&mut v, data.len() as u32);
        w32(&mut v, data.len() as u32);
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn reads_classic_pcap_stream_le_us() {
        let mut stream = pcap_header(MAGIC_US, false, 1);
        stream.extend(pcap_record(false, 100, 250_000, &[0xAA; 40]));
        stream.extend(pcap_record(false, 101, 0, &[0xBB; 60]));

        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        assert_eq!(r.linktype(), 1);
        let f1 = r.next_frame().unwrap().unwrap();
        assert_eq!((f1.ts_sec, f1.ts_nanos), (100, 250_000_000));
        assert_eq!(f1.data.len(), 40);
        let f2 = r.next_frame().unwrap().unwrap();
        assert_eq!(f2.data, vec![0xBB; 60]);
        assert!(r.next_frame().unwrap().is_none(), "clean EOF");
    }

    #[test]
    fn reads_classic_pcap_stream_be_nanos() {
        let mut stream = pcap_header(MAGIC_NS, true, 227);
        stream.extend(pcap_record(true, 7, 123_456_789, &[1, 2, 3]));
        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        assert_eq!(r.linktype(), 227);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!((f.ts_sec, f.ts_nanos), (7, 123_456_789));
        assert_eq!(f.data, vec![1, 2, 3]);
    }

    #[test]
    fn stream_cut_mid_record_is_an_error_not_a_frame() {
        let mut stream = pcap_header(MAGIC_US, false, 1);
        let rec = pcap_record(false, 1, 0, &[0xCC; 50]);
        stream.extend_from_slice(&rec[..20]); // header + 4 data bytes only
        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        assert!(r.next_frame().is_err());
    }

    #[test]
    fn rejects_non_capture_stream() {
        let err = PcapStreamReader::new(&b"tcpdump: syntax error\n"[..]).err().unwrap();
        assert!(err.to_string().contains("not a pcap/pcapng stream"), "{err}");
    }

    // ---- pcapng streaming ----

    fn ng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
        let total = 12 + body.len().div_ceil(4) * 4;
        let mut v = Vec::new();
        v.extend_from_slice(&block_type.to_le_bytes());
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v.extend_from_slice(body);
        v.extend(std::iter::repeat_n(0u8, total - 12 - body.len()));
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v
    }

    fn ng_shb() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&PCAPNG_BYTE_ORDER.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major
        body.extend_from_slice(&0u16.to_le_bytes()); // minor
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
        ng_block(PCAPNG_SHB, &body)
    }

    fn ng_idb(linktype: u16, tsresol: Option<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&linktype.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&65535u32.to_le_bytes());
        if let Some(v) = tsresol {
            body.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&[v, 0, 0, 0]); // value + pad
            body.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
        }
        ng_block(BLOCK_IDB, &body)
    }

    fn ng_epb(iface: u32, ts: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&iface.to_le_bytes());
        body.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ts as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        ng_block(BLOCK_EPB, &body)
    }

    #[test]
    fn reads_pcapng_stream_with_tsresol() {
        let mut stream = ng_shb();
        stream.extend(ng_idb(1, Some(3))); // millisecond resolution
        stream.extend(ng_epb(0, 1_700_000_000_123, &[0xEE; 30]));
        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        assert_eq!(r.linktype(), 1);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.ts_sec, 1_700_000_000);
        assert_eq!(f.ts_nanos, 123_000_000);
        assert_eq!(f.data.len(), 30);
        assert!(r.next_frame().unwrap().is_none());
    }

    #[test]
    fn pcapng_default_resolution_is_microseconds() {
        let mut stream = ng_shb();
        stream.extend(ng_idb(1, None));
        stream.extend(ng_epb(0, 5_000_000, &[1]));
        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!((f.ts_sec, f.ts_nanos), (5, 0));
    }

    #[test]
    fn pcapng_skips_unknown_blocks() {
        let mut stream = ng_shb();
        stream.extend(ng_idb(1, None));
        stream.extend(ng_block(0x0000_0005, &[0u8; 16])); // stats block
        stream.extend(ng_epb(0, 0, &[9, 9]));
        let mut r = PcapStreamReader::new(stream.as_slice()).unwrap();
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.data, vec![9, 9]);
    }

    #[test]
    fn tsresol_conversion() {
        assert_eq!(tsresol_to_tps(6), 1_000_000);
        assert_eq!(tsresol_to_tps(9), 1_000_000_000);
        assert_eq!(tsresol_to_tps(0x80 | 10), 1024);
        assert_eq!(tsresol_to_tps(200), DEFAULT_TPS); // insane exponent
    }

    // ---- remote command construction ----

    #[test]
    fn ssh_command_defaults() {
        let spec = RemoteSpec {
            host: "10.0.0.5".into(),
            ..Default::default()
        };
        let (prog, args) = spec.command();
        assert_eq!(prog, "ssh");
        assert!(args.contains(&"BatchMode=yes".into()));
        assert!(args.contains(&"10.0.0.5".into()));
        assert_eq!(
            args.last().unwrap(),
            "tcpdump -U -n -i any -s 0 -w -"
        );
    }

    #[test]
    fn ssh_command_full_options() {
        let spec = RemoteSpec {
            host: "router.lan".into(),
            user: Some("admin".into()),
            port: Some(2222),
            identity_file: Some("/home/me/.ssh/id_ed25519".into()),
            interface: Some("eth0".into()),
            capture_filter: Some("dns".into()),
            use_sudo: true,
            remote_command: None,
        };
        let (_, args) = spec.command();
        assert!(args.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["-i", "/home/me/.ssh/id_ed25519"]));
        assert!(args.contains(&"admin@router.lan".into()));
        // Friendly filter names are translated before shipping to tcpdump.
        assert_eq!(
            args.last().unwrap(),
            "sudo tcpdump -U -n -i eth0 -s 0 -w - 'udp port 53'"
        );
        assert_eq!(spec.describe(), "admin@router.lan:eth0");
    }

    #[test]
    fn remote_command_override_wins() {
        let spec = RemoteSpec {
            host: "sw1".into(),
            remote_command: Some("dumpcap -i eth1 -w - -f 'port 22'".into()),
            interface: Some("ignored".into()),
            ..Default::default()
        };
        assert_eq!(
            spec.remote_shell_command(),
            "dumpcap -i eth1 -w - -f 'port 22'"
        );
    }

    #[test]
    fn shell_quote_escapes() {
        assert_eq!(shell_quote("eth0"), "eth0");
        assert_eq!(shell_quote("port 53"), "'port 53'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn parses_extcap_interface_lines() {
        let text = "extcap {version=1.5.3.0}\n\
                    interface {value=\\\\.\\USBPcap1}{display=USBPcap1}\n\
                    interface {value=\\\\.\\USBPcap2}{display=USBPcap2: hub ports}\n";
        let ifs = parse_extcap_interfaces(text);
        assert_eq!(ifs.len(), 2);
        assert_eq!(ifs[0].0, "\\\\.\\USBPcap1");
        assert_eq!(ifs[1].1, "USBPcap2: hub ports");
    }
}
