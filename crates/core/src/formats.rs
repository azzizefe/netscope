// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Capture-file format detection & import — read formats beyond libpcap's
//! pcap/pcapng, the way Wireshark's Wiretap library does.
//!
//! [`RecordReader::open`] sniffs a file and yields a uniform stream of
//! [`RawFrame`]s plus the capture's link type, so the rest of netscope
//! (dissectors, merge/split, "open file") works the same whatever the source
//! format was. Supported:
//!
//! | Format | Detection | Notes |
//! |--------|-----------|-------|
//! | classic **pcap** (µs/ns, either endianness) | magic | via [`crate::remote::PcapStreamReader`] |
//! | **pcapng** | magic | idem; multi-interface, ns timestamps |
//! | **modified pcap** (Kuznetsov) | magic `a1b2cd34` | extra per-record ifindex/proto fields skipped |
//! | **snoop** (RFC 1761, Solaris) | magic `snoop\0\0\0` | big-endian; datalink mapped to DLT |
//! | **ERF** (Endace) | heuristic / `.erf` | TYPE_ETH and IPv4/IPv6 records |
//! | **K12 text** (Tektronix) | heuristic text scan | time-of-day timestamps |
//!
//! Everything is converted to the same `RawFrame` shape used by live capture,
//! so an imported snoop file dissects and re-saves exactly like a pcap.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};

use crate::pipeline::RawFrame;
use crate::remote::PcapStreamReader;

/// A recognised capture-file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap,
    PcapNg,
    ModifiedPcap,
    Snoop,
    Erf,
    K12Text,
    NetMon,
    Sniffer,
}

impl CaptureFormat {
    /// Human label for UIs and `info` output.
    pub fn label(&self) -> &'static str {
        match self {
            CaptureFormat::Pcap => "pcap",
            CaptureFormat::PcapNg => "pcapng",
            CaptureFormat::ModifiedPcap => "modified pcap (Kuznetsov)",
            CaptureFormat::Snoop => "snoop (RFC 1761)",
            CaptureFormat::Erf => "ERF (Endace)",
            CaptureFormat::K12Text => "K12 text (Tektronix)",
            CaptureFormat::NetMon => "Microsoft Network Monitor",
            CaptureFormat::Sniffer => "NetXray / Sniffer Classic",
        }
    }

    /// True for formats libpcap/our mmap reader already handle natively; the
    /// others need this module's importers.
    pub fn is_native_pcap(&self) -> bool {
        matches!(self, CaptureFormat::Pcap | CaptureFormat::PcapNg)
    }
}

// Magic numbers (first four bytes, read little-endian).
const PCAP_US: u32 = 0xa1b2_c3d4;
const PCAP_NS: u32 = 0xa1b2_3c4d;
const PCAP_US_SW: u32 = 0xd4c3_b2a1;
const PCAP_NS_SW: u32 = 0x4d3c_b2a1;
const PCAP_MOD: u32 = 0xa1b2_cd34;
const PCAP_MOD_SW: u32 = 0x34cd_b2a1;
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const SNOOP_MAGIC: &[u8; 8] = b"snoop\0\0\0";

/// Sniff a capture file's format from its first bytes (and, for the
/// header-less formats, a short heuristic parse).
pub fn detect(path: impl AsRef<Path>) -> Result<CaptureFormat> {
    let path = path.as_ref();
    let mut file =
        File::open(path).with_context(|| format!("cannot open '{}'", path.display()))?;
    let mut head = [0u8; 64];
    let n = read_up_to(&mut file, &mut head)?;
    let head = &head[..n];
    detect_bytes(head).ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' is not a capture file netscope recognises (pcap, pcapng, snoop, ERF, K12, NetMon or Sniffer)",
            path.display()
        )
    })
}

/// Format detection from a byte prefix — split out so it's unit-testable.
fn detect_bytes(head: &[u8]) -> Option<CaptureFormat> {
    if head.len() >= 9 && &head[..9] == b"trnsfile\0" {
        return Some(CaptureFormat::Sniffer);
    }
    if head.len() >= 8 && &head[..8] == SNOOP_MAGIC {
        return Some(CaptureFormat::Snoop);
    }
    if head.len() >= 4 {
        let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        match magic {
            PCAP_US | PCAP_NS | PCAP_US_SW | PCAP_NS_SW => return Some(CaptureFormat::Pcap),
            PCAP_MOD | PCAP_MOD_SW => return Some(CaptureFormat::ModifiedPcap),
            PCAPNG_SHB => return Some(CaptureFormat::PcapNg),
            _ => {}
        }
        if &head[..4] == b"GMBU" {
            return Some(CaptureFormat::NetMon);
        }
    }
    // Header-less / text formats: heuristics, most specific first.
    if looks_like_k12(head) {
        return Some(CaptureFormat::K12Text);
    }
    if looks_like_erf(head) {
        return Some(CaptureFormat::Erf);
    }
    None
}

/// A K12 text export starts with (or quickly reaches) its record separator
/// line of dashes, or a `time  PROTO` header. Require ASCII text so binary
/// captures never match.
fn looks_like_k12(head: &[u8]) -> bool {
    if !head.iter().all(|&b| b == b'\r' || b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b)) {
        return false;
    }
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => return false,
    };
    text.lines()
        .any(|l| l.starts_with("+---") || l.starts_with("|0   |") || l.starts_with("|0  |"))
}

/// Raw ERF has no file header, so plausibility-check the first record: a sane
/// record length that covers at least the 16-byte base header and a known
/// ERF type in the low 7 bits.
fn looks_like_erf(head: &[u8]) -> bool {
    if head.len() < 16 {
        return false;
    }
    let etype = head[8] & 0x7f;
    let rlen = u16::from_be_bytes([head[10], head[11]]);
    let wlen = u16::from_be_bytes([head[14], head[15]]);
    // ETH=2 is by far the common case; accept the small set we can dissect.
    // (wlen is u16, so its upper bound is implicit.)
    matches!(etype, 2 | 4 | 5) && rlen >= 16 && wlen > 0
}

/// A capture-file reader that produces [`RawFrame`]s regardless of the
/// on-disk format.
pub struct RecordReader {
    inner: ReaderKind,
    linktype: i32,
    format: CaptureFormat,
}

enum ReaderKind {
    /// pcap + pcapng via the shared streaming parser.
    Stream(Box<PcapStreamReader<File>>),
    Modified(ModifiedPcapReader),
    Snoop(SnoopReader),
    Erf(ErfReader),
    K12(K12Reader),
    NetMon(NetMonReader),
    Sniffer(SnifferReader),
}

impl RecordReader {
    /// Open `path`, detect its format, and prepare to stream frames.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let format = detect(path)?;
        let inner = match format {
            CaptureFormat::Pcap | CaptureFormat::PcapNg => {
                let file = File::open(path)?;
                let reader = PcapStreamReader::new(file)?;
                ReaderKind::Stream(Box::new(reader))
            }
            CaptureFormat::ModifiedPcap => ReaderKind::Modified(ModifiedPcapReader::open(path)?),
            CaptureFormat::Snoop => ReaderKind::Snoop(SnoopReader::open(path)?),
            CaptureFormat::Erf => ReaderKind::Erf(ErfReader::open(path)?),
            CaptureFormat::K12Text => ReaderKind::K12(K12Reader::open(path)?),
            CaptureFormat::NetMon => ReaderKind::NetMon(NetMonReader::open(path)?),
            CaptureFormat::Sniffer => ReaderKind::Sniffer(SnifferReader::open(path)?),
        };
        let linktype = match &inner {
            ReaderKind::Stream(r) => r.linktype(),
            ReaderKind::Modified(r) => r.linktype,
            ReaderKind::Snoop(r) => r.linktype,
            ReaderKind::Erf(_) => 1,       // ERF records we import are Ethernet
            ReaderKind::K12(r) => r.linktype,
            ReaderKind::NetMon(r) => r.linktype,
            ReaderKind::Sniffer(r) => r.linktype,
        };
        Ok(Self { inner, linktype, format })
    }

    /// The capture's link-layer type (first interface's, for multi-interface
    /// pcapng).
    pub fn linktype(&self) -> i32 {
        self.linktype
    }

    /// The detected on-disk format.
    pub fn format(&self) -> CaptureFormat {
        self.format
    }

    /// Next frame, `Ok(None)` at a clean end of file.
    pub fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        match &mut self.inner {
            ReaderKind::Stream(r) => r.next_frame(),
            ReaderKind::Modified(r) => r.next_frame(),
            ReaderKind::Snoop(r) => r.next_frame(),
            ReaderKind::Erf(r) => r.next_frame(),
            ReaderKind::K12(r) => Ok(r.next_frame()),
            ReaderKind::NetMon(r) => r.next_frame(),
            ReaderKind::Sniffer(r) => r.next_frame(),
        }
    }

    /// Collect every remaining frame. Convenience for callers that want the
    /// whole capture in memory (merge, info).
    pub fn read_all(&mut self) -> Result<Vec<RawFrame>> {
        let mut out = Vec::new();
        while let Some(f) = self.next_frame()? {
            out.push(f);
        }
        Ok(out)
    }
}

// ---- modified pcap (Alexey Kuznetsov's patched libpcap) ----------------------

/// Reads the "modified" pcap variant: a normal 24-byte global header but a
/// 24-byte per-record header (the standard 16 plus ifindex/protocol/pkt_type).
struct ModifiedPcapReader {
    file: BufReader<File>,
    swapped: bool,
    nanos: bool,
    linktype: i32,
}

impl ModifiedPcapReader {
    fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let mut hdr = [0u8; 24];
        file.read_exact(&mut hdr)
            .context("modified pcap: truncated global header")?;
        let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let swapped = magic == PCAP_MOD_SW;
        let rd_u32 = |b: &[u8]| rd32(b, swapped);
        let linktype = rd_u32(&hdr[20..24]) as i32;
        Ok(Self { file, swapped, nanos: false, linktype })
    }

    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        let mut hdr = [0u8; 24];
        if !fill(&mut self.file, &mut hdr)? {
            return Ok(None);
        }
        let ts_sec = rd32(&hdr[0..4], self.swapped);
        let ts_frac = rd32(&hdr[4..8], self.swapped);
        let caplen = rd32(&hdr[8..12], self.swapped);
        let orig_len = rd32(&hdr[12..16], self.swapped);
        // hdr[16..24] = ifindex(4), protocol(2), pkt_type(1), pad(1) — skipped.
        if caplen > MAX_CAPLEN {
            anyhow::bail!("modified pcap: corrupt record length {caplen}");
        }
        let mut data = vec![0u8; caplen as usize];
        self.file
            .read_exact(&mut data)
            .context("modified pcap: truncated record")?;
        Ok(Some(RawFrame {
            ts_sec: ts_sec as i64,
            ts_nanos: if self.nanos { ts_frac } else { ts_frac.saturating_mul(1000) },
            orig_len,
            data,
        }))
    }
}

// ---- snoop (RFC 1761) --------------------------------------------------------

/// Reads Sun/Solaris snoop captures. Big-endian throughout; records are
/// 4-byte aligned via the `record_length` field.
struct SnoopReader {
    file: BufReader<File>,
    linktype: i32,
}

impl SnoopReader {
    fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let mut hdr = [0u8; 16];
        file.read_exact(&mut hdr)
            .context("snoop: truncated file header")?;
        if &hdr[..8] != SNOOP_MAGIC {
            anyhow::bail!("snoop: bad magic");
        }
        let datalink = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        Ok(Self { file, linktype: snoop_datalink_to_dlt(datalink) })
    }

    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        let mut hdr = [0u8; 24];
        if !fill(&mut self.file, &mut hdr)? {
            return Ok(None);
        }
        let orig_len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let incl_len = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let rec_len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
        let ts_sec = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let ts_usec = u32::from_be_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
        if incl_len > MAX_CAPLEN || rec_len < 24 {
            anyhow::bail!("snoop: corrupt record (incl_len {incl_len}, rec_len {rec_len})");
        }
        let mut data = vec![0u8; incl_len as usize];
        self.file
            .read_exact(&mut data)
            .context("snoop: truncated record")?;
        // record_length covers the header + captured data + padding to 4 bytes.
        let consumed = 24 + incl_len as usize;
        if rec_len > consumed {
            skip(&mut self.file, (rec_len - consumed) as u64)?;
        }
        Ok(Some(RawFrame {
            ts_sec: ts_sec as i64,
            ts_nanos: ts_usec.saturating_mul(1000),
            orig_len,
            data,
        }))
    }
}

/// Map a snoop `datalink type` to the equivalent libpcap DLT. Ethernet
/// dominates real snoop captures; the rarer link types fall back to Ethernet
/// so at least the IP layer still dissects.
fn snoop_datalink_to_dlt(dl: u32) -> i32 {
    match dl {
        4 => 1,   // Ethernet → DLT_EN10MB
        0 => 1,   // IEEE 802.3 → treat as Ethernet
        2 => 6,   // token ring → DLT_IEEE802
        8 => 10,  // FDDI → DLT_FDDI
        _ => 1,
    }
}

// ---- ERF (Endace Extensible Record Format) ----------------------------------

/// Reads raw ERF records. There is no file header; each record self-describes
/// its length. We import the Ethernet and IP record types (the common ones);
/// others are skipped by their `rlen`.
struct ErfReader {
    file: BufReader<File>,
}

// ERF record types (low 7 bits of the type byte).
const ERF_TYPE_ETH: u8 = 2;
const ERF_TYPE_IPV4: u8 = 4;
const ERF_TYPE_IPV6: u8 = 5;
const ERF_EXT_HDR: u8 = 0x80; // "more extension headers" bit

impl ErfReader {
    fn open(path: &Path) -> Result<Self> {
        Ok(Self { file: BufReader::new(File::open(path)?) })
    }

    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        loop {
            let mut hdr = [0u8; 16];
            if !fill(&mut self.file, &mut hdr)? {
                return Ok(None);
            }
            // 64-bit ERF timestamp, little-endian: high 32 = seconds,
            // low 32 = fraction in units of 1/2^32 second.
            let ts = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
            let ts_sec = (ts >> 32) as i64;
            let frac = ts & 0xFFFF_FFFF;
            let ts_nanos = (frac * 1_000_000_000 / (1u64 << 32)) as u32;

            let type_byte = hdr[8];
            let etype = type_byte & 0x7f;
            let rlen = u16::from_be_bytes([hdr[10], hdr[11]]) as usize;
            if rlen < 16 {
                anyhow::bail!("ERF: record length {rlen} shorter than header");
            }
            // Body = everything after the 16-byte record header.
            let mut body = vec![0u8; rlen - 16];
            self.file
                .read_exact(&mut body)
                .context("ERF: truncated record")?;

            // Skip 8-byte extension headers (chained via each one's high bit).
            let mut off = 0usize;
            if type_byte & ERF_EXT_HDR != 0 {
                while off + 8 <= body.len() {
                    let more = body[off] & ERF_EXT_HDR != 0;
                    off += 8;
                    if !more {
                        break;
                    }
                }
            }

            let frame = match etype {
                ERF_TYPE_ETH => {
                    // Ethernet records carry a 2-byte offset/pad before the frame.
                    if off + 2 > body.len() {
                        continue;
                    }
                    let data = body[off + 2..].to_vec();
                    RawFrame { ts_sec, ts_nanos, orig_len: data.len() as u32, data }
                }
                ERF_TYPE_IPV4 | ERF_TYPE_IPV6 => {
                    let data = body[off..].to_vec();
                    RawFrame { ts_sec, ts_nanos, orig_len: data.len() as u32, data }
                }
                _ => continue, // unsupported record type — skip to the next
            };
            return Ok(Some(frame));
        }
    }
}

// ---- K12 text (Tektronix) ----------------------------------------------------

/// Reads Tektronix K12 text exports. The format is line-oriented: records are
/// separated by a `+---…` rule, a `HH:MM:SS,ms,us  PROTO` line gives the time
/// and encapsulation, and `|offset |xx|xx|…` lines carry the hex bytes.
///
/// K12 text has no capture date, only a time of day, so timestamps are
/// seconds-within-the-day (a synthetic epoch that still preserves ordering).
struct K12Reader {
    records: std::vec::IntoIter<RawFrame>,
    linktype: i32,
}

impl K12Reader {
    fn open(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("K12: cannot read text file")?;
        let (records, linktype) = parse_k12(&text);
        Ok(Self { records: records.into_iter(), linktype })
    }

    fn next_frame(&mut self) -> Option<RawFrame> {
        self.records.next()
    }
}

/// Parse a whole K12 text file into frames plus the detected link type.
fn parse_k12(text: &str) -> (Vec<RawFrame>, i32) {
    let mut frames = Vec::new();
    let mut linktype = 1; // Ethernet default

    let mut cur_time: Option<(i64, u32)> = None;
    let mut cur_bytes: Vec<u8> = Vec::new();
    let mut have_record = false;

    let flush = |frames: &mut Vec<RawFrame>,
                 time: &mut Option<(i64, u32)>,
                 bytes: &mut Vec<u8>,
                 have: &mut bool| {
        if *have && !bytes.is_empty() {
            let (ts_sec, ts_nanos) = time.unwrap_or((0, 0));
            frames.push(RawFrame {
                ts_sec,
                ts_nanos,
                orig_len: bytes.len() as u32,
                data: std::mem::take(bytes),
            });
        }
        bytes.clear();
        *time = None;
        *have = false;
    };

    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.starts_with("+---") {
            // Record boundary: emit whatever we accumulated.
            flush(&mut frames, &mut cur_time, &mut cur_bytes, &mut have_record);
            have_record = true;
            continue;
        }
        if let Some((t, proto)) = parse_k12_time_line(trimmed) {
            cur_time = Some(t);
            have_record = true;
            if let Some(lt) = k12_encap_to_dlt(&proto) {
                linktype = lt;
            }
            continue;
        }
        if trimmed.starts_with('|') {
            append_k12_hex(trimmed, &mut cur_bytes);
            have_record = true;
        }
    }
    flush(&mut frames, &mut cur_time, &mut cur_bytes, &mut have_record);
    (frames, linktype)
}

/// Parse a `HH:MM:SS,ms,us   PROTO` header → ((sec, nanos), proto). The time
/// becomes seconds within a day so ordering is preserved without a date.
fn parse_k12_time_line(line: &str) -> Option<((i64, u32), String)> {
    let mut it = line.split_whitespace();
    let time = it.next()?;
    let proto = it.next().unwrap_or("").to_string();
    // time = HH:MM:SS,mmm,uuu  (comma-separated sub-seconds)
    let (hms, frac) = time.split_once(',')?;
    let mut hp = hms.split(':');
    let h: i64 = hp.next()?.parse().ok()?;
    let m: i64 = hp.next()?.parse().ok()?;
    let s: i64 = hp.next()?.parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) || !(0..60).contains(&s) {
        return None;
    }
    // frac may be "mmm,uuu" (ms then µs) or just "mmm".
    let mut nanos: u32 = 0;
    let mut parts = frac.split(',');
    if let Some(ms) = parts.next().and_then(|v| v.parse::<u32>().ok()) {
        nanos += ms.min(999) * 1_000_000;
    }
    if let Some(us) = parts.next().and_then(|v| v.parse::<u32>().ok()) {
        nanos += us.min(999) * 1_000;
    }
    let secs = h * 3600 + m * 60 + s;
    Some(((secs, nanos), proto))
}

/// Append the hex bytes on a `|offset |xx|xx|…` line to the frame buffer.
fn append_k12_hex(line: &str, out: &mut Vec<u8>) {
    // Fields are pipe-separated; the first is the offset, the rest are bytes.
    for field in line.split('|').skip(2) {
        let f = field.trim();
        if f.len() == 2 {
            if let Ok(b) = u8::from_str_radix(f, 16) {
                out.push(b);
            }
        }
    }
}

/// Map a K12 encapsulation name to a libpcap DLT.
fn k12_encap_to_dlt(proto: &str) -> Option<i32> {
    match proto.to_ascii_uppercase().as_str() {
        "ETHER" | "ETHERNET" => Some(1),
        "" => None,
        _ => Some(1), // unknown encapsulations import as Ethernet
    }
}

// ---- NetMon (Microsoft Network Monitor 2.x) ----------------------------------

struct NetMonReader {
    file: File,
    offsets: Vec<u32>,
    current_idx: usize,
    linktype: i32,
    start_sec: i64,
    start_nanos: u32,
}

impl NetMonReader {
    fn open(path: &Path) -> Result<Self> {
        use std::io::Seek;
        let mut file = File::open(path)?;
        let mut hdr = [0u8; 128];
        file.read_exact(&mut hdr)
            .context("NetMon: truncated file header")?;
        
        if &hdr[..4] != b"GMBU" {
            anyhow::bail!("NetMon: bad magic");
        }
        
        let mac_type = u16::from_le_bytes([hdr[6], hdr[7]]);
        let linktype = match mac_type {
            1 => 1,   // Ethernet
            6 => 6,   // Token Ring
            2 => 10,  // FDDI
            18 => 105, // 802.11
            _ => 1,
        };
        
        let wyear = u16::from_le_bytes([hdr[8], hdr[9]]);
        let wmonth = u16::from_le_bytes([hdr[10], hdr[11]]);
        let wday = u16::from_le_bytes([hdr[14], hdr[15]]);
        let whour = u16::from_le_bytes([hdr[16], hdr[17]]);
        let wminute = u16::from_le_bytes([hdr[18], hdr[19]]);
        let wsecond = u16::from_le_bytes([hdr[20], hdr[21]]);
        let wmillis = u16::from_le_bytes([hdr[22], hdr[23]]);
        
        let start_sec = if wyear >= 1970 {
            let days_since_epoch = (wyear as i64 - 1970) * 365 + (wyear as i64 - 1968) / 4;
            (days_since_epoch * 86400) + (wmonth as i64 * 30 * 86400) + (wday as i64 * 86400) + (whour as i64 * 3600) + (wminute as i64 * 60) + wsecond as i64
        } else {
            0
        };
        let start_nanos = wmillis as u32 * 1_000_000;
        
        let frame_table_offset = u32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
        let frame_table_length = u32::from_le_bytes([hdr[28], hdr[29], hdr[30], hdr[31]]);
        
        let num_frames = (frame_table_length / 4) as usize;
        file.seek(std::io::SeekFrom::Start(frame_table_offset as u64))
            .context("NetMon: failed to seek to frame table")?;
        
        let mut offsets = vec![0u32; num_frames];
        let mut offsets_bytes = vec![0u8; frame_table_length as usize];
        file.read_exact(&mut offsets_bytes)
            .context("NetMon: truncated frame table")?;
        
        for i in 0..num_frames {
            let start = i * 4;
            offsets[i] = u32::from_le_bytes([
                offsets_bytes[start],
                offsets_bytes[start + 1],
                offsets_bytes[start + 2],
                offsets_bytes[start + 3],
            ]);
        }
        
        Ok(Self {
            file,
            offsets,
            current_idx: 0,
            linktype,
            start_sec,
            start_nanos,
        })
    }
    
    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        use std::io::Seek;
        if self.current_idx >= self.offsets.len() {
            return Ok(None);
        }
        let offset = self.offsets[self.current_idx];
        self.current_idx += 1;
        
        self.file.seek(std::io::SeekFrom::Start(offset as u64))
            .context("NetMon: failed to seek to frame offset")?;
        
        let mut frame_hdr = [0u8; 16];
        self.file.read_exact(&mut frame_hdr)
            .context("NetMon: truncated frame record header")?;
        
        let ts_delta = u64::from_le_bytes(frame_hdr[0..8].try_into().unwrap());
        let orig_len = u32::from_le_bytes(frame_hdr[8..12].try_into().unwrap());
        let incl_len = u32::from_le_bytes(frame_hdr[12..16].try_into().unwrap());
        
        if incl_len > MAX_CAPLEN {
            anyhow::bail!("NetMon: corrupt record length {incl_len}");
        }
        
        let mut data = vec![0u8; incl_len as usize];
        self.file.read_exact(&mut data)
            .context("NetMon: truncated frame record payload")?;
            
        let delta_secs = (ts_delta / 1_000_000) as i64;
        let delta_nanos = ((ts_delta % 1_000_000) * 1_000) as u32;
        
        let mut ts_sec = self.start_sec + delta_secs;
        let mut ts_nanos = self.start_nanos + delta_nanos;
        if ts_nanos >= 1_000_000_000 {
            ts_sec += 1;
            ts_nanos -= 1_000_000_000;
        }
        
        Ok(Some(RawFrame {
            ts_sec,
            ts_nanos,
            orig_len,
            data,
        }))
    }
}

// ---- Sniffer (NetXray / Sniffer Classic) -------------------------------------

struct SnifferReader {
    file: BufReader<File>,
    linktype: i32,
    start_sec: i64,
}

impl SnifferReader {
    fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let mut hdr = [0u8; 64];
        file.read_exact(&mut hdr)
            .context("Sniffer: truncated file header")?;
        
        if &hdr[..9] != b"trnsfile\0" {
            anyhow::bail!("Sniffer: bad magic");
        }
        
        let mac_type = hdr[16];
        let linktype = match mac_type {
            1 => 1,   // Ethernet
            2 => 6,   // Token Ring
            _ => 1,
        };
        
        Ok(Self {
            file,
            linktype,
            start_sec: 1_700_000_000,
        })
    }
    
    fn next_frame(&mut self) -> Result<Option<RawFrame>> {
        let mut record_hdr = [0u8; 16];
        if !fill(&mut self.file, &mut record_hdr)? {
            return Ok(None);
        }
        
        let ts_val = u64::from_le_bytes(record_hdr[0..8].try_into().unwrap());
        let incl_len = u16::from_le_bytes(record_hdr[8..10].try_into().unwrap()) as u32;
        let orig_len = u16::from_le_bytes(record_hdr[10..12].try_into().unwrap()) as u32;
        
        if incl_len > MAX_CAPLEN || incl_len == 0 {
            return Ok(None);
        }
        
        let mut data = vec![0u8; incl_len as usize];
        self.file.read_exact(&mut data)
            .context("Sniffer: truncated frame payload")?;
            
        let ts_sec = self.start_sec + (ts_val / 1_000_000) as i64;
        let ts_nanos = ((ts_val % 1_000_000) * 1_000) as u32;
        
        Ok(Some(RawFrame {
            ts_sec,
            ts_nanos,
            orig_len,
            data,
        }))
    }
}

// ---- shared byte helpers -----------------------------------------------------

const MAX_CAPLEN: u32 = 64 * 1024 * 1024;

fn rd32(b: &[u8], swapped: bool) -> u32 {
    let raw = [b[0], b[1], b[2], b[3]];
    if swapped {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

/// Fill `buf` fully. `Ok(false)` on clean EOF before the first byte; an EOF
/// mid-buffer is an error.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                anyhow::bail!("capture file ended mid-record");
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Read up to `buf.len()` bytes, returning how many arrived (short read at EOF
/// is fine — used only for format sniffing).
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// Discard `n` bytes from a non-seekable reader.
fn skip<R: Read>(r: &mut R, mut n: u64) -> Result<()> {
    let mut scratch = [0u8; 512];
    while n > 0 {
        let take = scratch.len().min(n as usize);
        r.read_exact(&mut scratch[..take])
            .context("capture file ended during inter-record padding")?;
        n -= take as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "netscope-fmt-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    // ---- detection ----

    #[test]
    fn detects_by_magic() {
        assert_eq!(detect_bytes(&PCAP_US.to_le_bytes()), Some(CaptureFormat::Pcap));
        assert_eq!(detect_bytes(&PCAP_NS.to_le_bytes()), Some(CaptureFormat::Pcap));
        assert_eq!(detect_bytes(&PCAP_MOD.to_le_bytes()), Some(CaptureFormat::ModifiedPcap));
        assert_eq!(detect_bytes(&PCAPNG_SHB.to_le_bytes()), Some(CaptureFormat::PcapNg));
        assert_eq!(detect_bytes(SNOOP_MAGIC), Some(CaptureFormat::Snoop));
    }

    // ---- snoop ----

    fn snoop_file(datalink: u32, frames: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(SNOOP_MAGIC);
        v.extend_from_slice(&2u32.to_be_bytes()); // version
        v.extend_from_slice(&datalink.to_be_bytes());
        for (i, f) in frames.iter().enumerate() {
            let incl = f.len() as u32;
            let pad = (4 - f.len() % 4) % 4;
            let rec_len = 24 + f.len() + pad;
            v.extend_from_slice(&incl.to_be_bytes()); // orig_len
            v.extend_from_slice(&incl.to_be_bytes()); // incl_len
            v.extend_from_slice(&(rec_len as u32).to_be_bytes());
            v.extend_from_slice(&0u32.to_be_bytes()); // cum drops
            v.extend_from_slice(&(1_700_000_000u32 + i as u32).to_be_bytes());
            v.extend_from_slice(&(i as u32 * 1000).to_be_bytes());
            v.extend_from_slice(f);
            v.extend(std::iter::repeat_n(0u8, pad));
        }
        v
    }

    #[test]
    fn reads_snoop_ethernet() {
        let p = temp("snoop", &snoop_file(4, &[&[0xAA; 5], &[0xBB; 8]]));
        assert_eq!(detect(&p).unwrap(), CaptureFormat::Snoop);
        let mut r = RecordReader::open(&p).unwrap();
        assert_eq!(r.linktype(), 1);
        let f1 = r.next_frame().unwrap().unwrap();
        assert_eq!(f1.ts_sec, 1_700_000_000);
        assert_eq!(f1.data, vec![0xAA; 5]);
        let f2 = r.next_frame().unwrap().unwrap();
        assert_eq!(f2.data, vec![0xBB; 8]);
        assert!(r.next_frame().unwrap().is_none());
        std::fs::remove_file(p).ok();
    }

    // ---- modified pcap ----

    #[test]
    fn reads_modified_pcap() {
        let mut v = Vec::new();
        v.extend_from_slice(&PCAP_MOD.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        let data = [0xCD; 12];
        v.extend_from_slice(&1_700_000_005u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&7u32.to_le_bytes()); // ifindex
        v.extend_from_slice(&0u16.to_le_bytes()); // protocol
        v.push(0); // pkt_type
        v.push(0); // pad
        v.extend_from_slice(&data);

        let p = temp("modpcap", &v);
        assert_eq!(detect(&p).unwrap(), CaptureFormat::ModifiedPcap);
        let mut r = RecordReader::open(&p).unwrap();
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.ts_sec, 1_700_000_005);
        assert_eq!(f.data, vec![0xCD; 12]);
        assert!(r.next_frame().unwrap().is_none());
        std::fs::remove_file(p).ok();
    }

    // ---- ERF ----

    #[test]
    fn reads_erf_ethernet() {
        // One ERF TYPE_ETH record: ts, type=2, flags, rlen, color, wlen,
        // then 2-byte pad + Ethernet-ish payload.
        let payload = [0xEE; 20];
        let rlen = 16 + 2 + payload.len();
        let mut v = Vec::new();
        let ts: u64 = (1_700_000_000u64 << 32) | (1u64 << 31); // .5 second
        v.extend_from_slice(&ts.to_le_bytes());
        v.push(ERF_TYPE_ETH);
        v.push(0); // flags
        v.extend_from_slice(&(rlen as u16).to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // color
        v.extend_from_slice(&(payload.len() as u16 + 2).to_be_bytes()); // wlen
        v.extend_from_slice(&[0, 0]); // eth offset/pad
        v.extend_from_slice(&payload);

        let p = temp("erf", &v);
        assert_eq!(detect(&p).unwrap(), CaptureFormat::Erf);
        let mut r = RecordReader::open(&p).unwrap();
        assert_eq!(r.linktype(), 1);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.ts_sec, 1_700_000_000);
        assert_eq!(f.ts_nanos, 500_000_000);
        assert_eq!(f.data, vec![0xEE; 20]);
        std::fs::remove_file(p).ok();
    }

    // ---- K12 text ----

    #[test]
    fn reads_k12_text() {
        let text = "\
+---------+---------------+----------+
08:15:30,123,456   ETHER
|0   |00|11|22|33|44|55|66|77|
|8   |88|99|
+---------+---------------+----------+
08:15:31,000,000   ETHER
|0   |AA|BB|CC|DD|
";
        let p = temp("k12", text.as_bytes());
        assert_eq!(detect(&p).unwrap(), CaptureFormat::K12Text);
        let mut r = RecordReader::open(&p).unwrap();
        assert_eq!(r.linktype(), 1);
        let f1 = r.next_frame().unwrap().unwrap();
        assert_eq!(f1.data, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
        assert_eq!(f1.ts_sec, 8 * 3600 + 15 * 60 + 30);
        assert_eq!(f1.ts_nanos, 123 * 1_000_000 + 456 * 1_000);
        let f2 = r.next_frame().unwrap().unwrap();
        assert_eq!(f2.data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(r.next_frame().unwrap().is_none());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn k12_time_parsing() {
        let ((s, n), proto) = parse_k12_time_line("08:15:30,123,456   ETHER").unwrap();
        assert_eq!(s, 8 * 3600 + 15 * 60 + 30);
        assert_eq!(n, 123_456_000);
        assert_eq!(proto, "ETHER");
        assert!(parse_k12_time_line("not a time line").is_none());
    }

    #[test]
    fn reads_netmon() {
        let mut v = vec![0u8; 128];
        v[0..4].copy_from_slice(b"GMBU");
        v[4] = 2; // major
        v[5] = 0; // minor
        v[6..8].copy_from_slice(&1u16.to_le_bytes()); // Ethernet mac_type
        // SYSTEMTIME fields (year=2026, month=7, day=14, hour=12, min=30, sec=45, ms=500)
        v[8..10].copy_from_slice(&2026u16.to_le_bytes());
        v[10..12].copy_from_slice(&7u16.to_le_bytes());
        v[14..16].copy_from_slice(&14u16.to_le_bytes());
        v[16..18].copy_from_slice(&12u16.to_le_bytes());
        v[18..20].copy_from_slice(&30u16.to_le_bytes());
        v[20..22].copy_from_slice(&45u16.to_le_bytes());
        v[22..24].copy_from_slice(&500u16.to_le_bytes());
        
        let frame_offset = 128u32;
        let frame_table_offset: u32 = 128 + 16 + 10; // offset after frame record
        let frame_table_length = 4u32;
        
        v[24..28].copy_from_slice(&frame_table_offset.to_le_bytes());
        v[28..32].copy_from_slice(&frame_table_length.to_le_bytes());
        
        // Frame Record at offset 128
        let mut rec = vec![0u8; 16];
        rec[0..8].copy_from_slice(&10_000_000u64.to_le_bytes()); // 10 seconds delta
        rec[8..12].copy_from_slice(&10u32.to_le_bytes()); // orig_len
        rec[12..16].copy_from_slice(&10u32.to_le_bytes()); // incl_len
        let payload = vec![0xFFu8; 10];
        
        v.extend_from_slice(&rec);
        v.extend_from_slice(&payload);
        
        // Frame Table at offset 154
        v.extend_from_slice(&frame_offset.to_le_bytes());
        
        let p = temp("netmon", &v);
        assert_eq!(detect(&p).unwrap(), CaptureFormat::NetMon);
        let mut r = RecordReader::open(&p).unwrap();
        assert_eq!(r.linktype(), 1);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.data, payload);
        assert_eq!(f.orig_len, 10);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn reads_sniffer() {
        let mut v = vec![0u8; 64];
        v[0..10].copy_from_slice(b"trnsfile\0\0");
        v[16] = 1; // mac_type Ethernet
        
        // Record: ts(8), incl_len(2), orig_len(2), extra(4), data
        let mut rec = vec![0u8; 16];
        rec[0..8].copy_from_slice(&5_000_000u64.to_le_bytes()); // 5 seconds
        rec[8..10].copy_from_slice(&8u16.to_le_bytes());
        rec[10..12].copy_from_slice(&8u16.to_le_bytes());
        let payload = vec![0xEEu8; 8];
        
        v.extend_from_slice(&rec);
        v.extend_from_slice(&payload);
        
        let p = temp("sniffer", &v);
        assert_eq!(detect(&p).unwrap(), CaptureFormat::Sniffer);
        let mut r = RecordReader::open(&p).unwrap();
        assert_eq!(r.linktype(), 1);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.data, payload);
        assert_eq!(f.ts_sec, 1_700_000_005);
        std::fs::remove_file(p).ok();
    }
}
