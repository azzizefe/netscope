//! Capture merge & split — netscope's take on Wireshark's `mergecap` and
//! `editcap`, plus a `capinfos`-style summary.
//!
//! * [`merge`] combines several capture files into one, interleaving packets
//!   in timestamp order (or concatenating them as-is). Inputs may be any
//!   format [`crate::formats`] reads (pcap, pcapng, snoop, ERF, K12…); the
//!   output is pcap or pcapng.
//! * [`split`] breaks one capture into numbered chunks by packet count, time
//!   span, or byte size.
//! * [`info`] reports the format, link type, packet count, byte total and
//!   time span of a capture file.
//!
//! Merging captures with different link types requires a pcapng output (one
//! interface block per input); a classic pcap can only hold a single link
//! type.

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::formats::{CaptureFormat, RecordReader};
use crate::pcapng::{InterfaceMeta, PcapngWriter, SectionMeta};
use crate::pipeline::RawFrame;
use crate::rotate::{RingBufferOptions, RingWriter};

/// Output container for merge/split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFormat {
    /// Classic pcap (single link type, microsecond timestamps).
    Pcap,
    /// pcapng (multi-interface, nanosecond timestamps, metadata).
    PcapNg,
}

impl WriteFormat {
    /// File extension for this format (no dot).
    pub fn ext(&self) -> &'static str {
        match self {
            WriteFormat::Pcap => "pcap",
            WriteFormat::PcapNg => "pcapng",
        }
    }

    /// The natural output format for re-writing a file of `input` format:
    /// pcapng stays pcapng, everything else becomes pcap.
    pub fn from_input(input: CaptureFormat) -> Self {
        if input == CaptureFormat::PcapNg {
            WriteFormat::PcapNg
        } else {
            WriteFormat::Pcap
        }
    }
}

/// A capture-file writer that hides the pcap-vs-pcapng difference. pcapng
/// writes carry `interface_id`; pcap ignores it (one link type only).
enum RecordWriter {
    Pcap(Option<RingWriter>),
    Ng(Option<PcapngWriter<BufWriter<File>>>),
}

impl RecordWriter {
    fn create(
        path: &Path,
        format: WriteFormat,
        interfaces: &[InterfaceMeta],
        section: SectionMeta,
    ) -> Result<Self> {
        match format {
            WriteFormat::Pcap => {
                let linktype = interfaces.first().map(|i| i.linktype).unwrap_or(1);
                let w = RingWriter::create(path, linktype, RingBufferOptions::default())
                    .with_context(|| format!("cannot create '{}'", path.display()))?;
                Ok(RecordWriter::Pcap(Some(w)))
            }
            WriteFormat::PcapNg => {
                let w = PcapngWriter::create(path, section, interfaces)
                    .with_context(|| format!("cannot create '{}'", path.display()))?;
                Ok(RecordWriter::Ng(Some(w)))
            }
        }
    }

    fn write(&mut self, interface_id: u32, f: &RawFrame) -> Result<()> {
        match self {
            RecordWriter::Pcap(w) => {
                let w = w.as_mut().expect("writer used after finish");
                w.write(
                    f.ts_sec.max(0) as u32,
                    f.ts_nanos / 1000,
                    f.orig_len,
                    &f.data,
                )?;
            }
            RecordWriter::Ng(w) => {
                let w = w.as_mut().expect("writer used after finish");
                w.write_packet(interface_id, f.ts_sec, f.ts_nanos, f.orig_len, &f.data, None)?;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<()> {
        match self {
            RecordWriter::Pcap(Some(w)) => w.finish()?,
            RecordWriter::Ng(Some(w)) => w.finish()?,
            _ => {}
        }
        Ok(())
    }
}

/// How to combine inputs in [`merge`].
#[derive(Debug, Clone)]
pub struct MergeOptions {
    /// Output container.
    pub format: WriteFormat,
    /// `true` (default): interleave in timestamp order. `false`: concatenate
    /// each input end-to-end in the order given.
    pub chronological: bool,
    /// Optional section comment recorded in a pcapng output.
    pub comment: Option<String>,
}

impl Default for MergeOptions {
    fn default() -> Self {
        Self { format: WriteFormat::PcapNg, chronological: true, comment: None }
    }
}

/// Result of a [`merge`].
#[derive(Debug, Clone)]
pub struct MergeStats {
    pub inputs: usize,
    pub packets: u64,
    pub output: PathBuf,
}

/// Merge `inputs` into `output`. Each input becomes its own pcapng interface
/// (preserving provenance and allowing mixed link types); a pcap output
/// requires every input to share one link type.
pub fn merge(inputs: &[PathBuf], output: &Path, opts: &MergeOptions) -> Result<MergeStats> {
    if inputs.is_empty() {
        anyhow::bail!("merge needs at least one input file");
    }

    // Open every input; keep its link type and a display name for the IDB.
    let mut readers = Vec::with_capacity(inputs.len());
    let mut interfaces = Vec::with_capacity(inputs.len());
    for path in inputs {
        let reader = RecordReader::open(path)
            .with_context(|| format!("cannot open '{}'", path.display()))?;
        interfaces.push(InterfaceMeta {
            linktype: reader.linktype(),
            snaplen: 0,
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()),
            description: None,
        });
        readers.push(reader);
    }

    let mixed_linktypes = interfaces.iter().any(|i| i.linktype != interfaces[0].linktype);
    if opts.format == WriteFormat::Pcap && mixed_linktypes {
        anyhow::bail!(
            "inputs have different link types — a classic pcap can't hold them; write pcapng instead"
        );
    }

    let section = SectionMeta {
        comment: opts.comment.clone(),
        application: Some(concat!("netscope ", env!("CARGO_PKG_VERSION")).to_string()),
        ..Default::default()
    };
    // pcap output collapses to one interface; pcapng keeps one per input.
    let out_interfaces: Vec<InterfaceMeta> = match opts.format {
        WriteFormat::Pcap => vec![interfaces[0].clone()],
        WriteFormat::PcapNg => interfaces.clone(),
    };
    let mut writer = RecordWriter::create(output, opts.format, &out_interfaces, section)?;

    let mut packets = 0u64;
    if opts.chronological {
        // Streaming k-way merge: hold one pending frame per input, always
        // emit the earliest, then refill from that input.
        let mut heads: Vec<Option<RawFrame>> = Vec::with_capacity(readers.len());
        for r in &mut readers {
            heads.push(r.next_frame()?);
        }
        loop {
            // Pick the input whose pending frame has the earliest timestamp.
            let mut pick: Option<usize> = None;
            for (i, head) in heads.iter().enumerate() {
                if let Some(f) = head {
                    let earlier = match pick {
                        None => true,
                        Some(p) => frame_key(f) < frame_key(heads[p].as_ref().unwrap()),
                    };
                    if earlier {
                        pick = Some(i);
                    }
                }
            }
            let Some(i) = pick else { break };
            let frame = heads[i].take().unwrap();
            let iface_id = if opts.format == WriteFormat::Pcap { 0 } else { i as u32 };
            writer.write(iface_id, &frame)?;
            packets += 1;
            heads[i] = readers[i].next_frame()?;
        }
    } else {
        // Concatenate: drain each input fully, in order.
        for (i, reader) in readers.iter_mut().enumerate() {
            let iface_id = if opts.format == WriteFormat::Pcap { 0 } else { i as u32 };
            while let Some(frame) = reader.next_frame()? {
                writer.write(iface_id, &frame)?;
                packets += 1;
            }
        }
    }

    writer.finish()?;
    Ok(MergeStats { inputs: inputs.len(), packets, output: output.to_path_buf() })
}

/// How to divide a capture in [`split`].
#[derive(Debug, Clone, Copy)]
pub enum SplitMode {
    /// At most this many packets per output file.
    Packets(usize),
    /// Start a new file once a packet is this many seconds past the chunk's
    /// first packet.
    Seconds(u64),
    /// Start a new file once adding a packet would exceed this many bytes of
    /// captured data.
    Bytes(u64),
}

/// Options for [`split`].
#[derive(Debug, Clone)]
pub struct SplitOptions {
    pub format: WriteFormat,
    pub mode: SplitMode,
}

/// Split `input` into numbered files named `<prefix-stem>_00001.<ext>` (the
/// prefix's own extension, if any, is replaced by the output format's).
/// Returns the paths written, in order.
pub fn split(input: &Path, output_prefix: &Path, opts: &SplitOptions) -> Result<Vec<PathBuf>> {
    let mut reader =
        RecordReader::open(input).with_context(|| format!("cannot open '{}'", input.display()))?;
    let interfaces = [InterfaceMeta {
        linktype: reader.linktype(),
        snaplen: 0,
        name: input.file_name().map(|n| n.to_string_lossy().into_owned()),
        description: None,
    }];

    let mut written = Vec::new();
    let mut writer: Option<RecordWriter> = None;
    let mut chunk_packets = 0usize;
    let mut chunk_bytes = 0u64;
    let mut chunk_start: Option<(i64, u32)> = None;

    while let Some(frame) = reader.next_frame()? {
        // Decide whether this frame starts a new chunk (never split before the
        // very first frame of a file).
        let boundary = writer.is_some()
            && match opts.mode {
                SplitMode::Packets(n) => chunk_packets >= n.max(1),
                SplitMode::Seconds(s) => chunk_start
                    .map(|start| {
                        frame_key(&frame).0 - start.0 >= s.max(1) as i64
                    })
                    .unwrap_or(false),
                SplitMode::Bytes(b) => {
                    chunk_bytes + frame.data.len() as u64 > b.max(1) && chunk_packets > 0
                }
            };
        if boundary {
            if let Some(w) = writer.take() {
                w.finish()?;
            }
        }
        if writer.is_none() {
            let path = split_name(output_prefix, written.len() + 1, opts.format.ext());
            let section = SectionMeta {
                application: Some(concat!("netscope ", env!("CARGO_PKG_VERSION")).to_string()),
                ..Default::default()
            };
            writer = Some(RecordWriter::create(&path, opts.format, &interfaces, section)?);
            written.push(path);
            chunk_packets = 0;
            chunk_bytes = 0;
            chunk_start = Some(frame_key(&frame));
        }
        writer.as_mut().unwrap().write(0, &frame)?;
        chunk_packets += 1;
        chunk_bytes += frame.data.len() as u64;
    }
    if let Some(w) = writer.take() {
        w.finish()?;
    }
    if written.is_empty() {
        anyhow::bail!("'{}' contained no packets to split", input.display());
    }
    Ok(written)
}

/// `capinfos`-style summary of a capture file.
#[derive(Debug, Clone)]
pub struct CaptureFileInfo {
    pub format: CaptureFormat,
    pub linktype: i32,
    pub packets: u64,
    pub data_bytes: u64,
    pub first: Option<(i64, u32)>,
    pub last: Option<(i64, u32)>,
}

impl CaptureFileInfo {
    /// Capture span in seconds (last − first timestamp), if known.
    pub fn duration_secs(&self) -> Option<f64> {
        match (self.first, self.last) {
            (Some(a), Some(b)) => {
                Some((b.0 - a.0) as f64 + (b.1 as f64 - a.1 as f64) / 1e9)
            }
            _ => None,
        }
    }
}

/// Read a capture file end-to-end and summarise it.
pub fn info(path: &Path) -> Result<CaptureFileInfo> {
    let mut reader = RecordReader::open(path)?;
    let format = reader.format();
    let linktype = reader.linktype();
    let mut packets = 0u64;
    let mut data_bytes = 0u64;
    let mut first = None;
    let mut last = None;
    while let Some(f) = reader.next_frame()? {
        let key = frame_key(&f);
        if first.is_none() {
            first = Some(key);
        }
        last = Some(key);
        packets += 1;
        data_bytes += f.data.len() as u64;
    }
    Ok(CaptureFileInfo { format, linktype, packets, data_bytes, first, last })
}

/// Sort key for a frame: `(seconds, nanoseconds)`.
fn frame_key(f: &RawFrame) -> (i64, u32) {
    (f.ts_sec, f.ts_nanos)
}

/// Build a split output name: `<prefix stem>_<NNNNN>.<ext>` in the prefix's
/// directory.
fn split_name(prefix: &Path, index: usize, ext: &str) -> PathBuf {
    let stem = prefix
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".into());
    let name = format!("{stem}_{index:05}.{ext}");
    match prefix.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::RecordReader;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "netscope-editcap-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write a classic pcap with frames at the given (sec, byte-fill) values.
    fn write_pcap(path: &Path, frames: &[(u32, u8, usize)]) {
        let mut w = RingWriter::create(path, 1, RingBufferOptions::default()).unwrap();
        for &(sec, fill, len) in frames {
            w.write(sec, 0, len as u32, &vec![fill; len]).unwrap();
        }
        w.finish().unwrap();
    }

    fn read_all(path: &Path) -> Vec<RawFrame> {
        let mut r = RecordReader::open(path).unwrap();
        r.read_all().unwrap()
    }

    #[test]
    fn merge_interleaves_by_timestamp() {
        let dir = tmp_dir("merge");
        let a = dir.join("a.pcap");
        let b = dir.join("b.pcap");
        write_pcap(&a, &[(10, 0xA0, 4), (30, 0xA1, 4)]);
        write_pcap(&b, &[(20, 0xB0, 4), (40, 0xB1, 4)]);

        let out = dir.join("merged.pcapng");
        let stats = merge(
            &[a, b],
            &out,
            &MergeOptions { format: WriteFormat::PcapNg, chronological: true, comment: None },
        )
        .unwrap();
        assert_eq!(stats.packets, 4);

        let frames = read_all(&out);
        let secs: Vec<i64> = frames.iter().map(|f| f.ts_sec).collect();
        assert_eq!(secs, vec![10, 20, 30, 40], "must be time-ordered");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn merge_concatenate_keeps_input_order() {
        let dir = tmp_dir("concat");
        let a = dir.join("a.pcap");
        let b = dir.join("b.pcap");
        write_pcap(&a, &[(30, 0xA0, 4)]);
        write_pcap(&b, &[(10, 0xB0, 4)]);
        let out = dir.join("cat.pcapng");
        merge(
            &[a, b],
            &out,
            &MergeOptions { format: WriteFormat::PcapNg, chronological: false, comment: None },
        )
        .unwrap();
        let secs: Vec<i64> = read_all(&out).iter().map(|f| f.ts_sec).collect();
        assert_eq!(secs, vec![30, 10], "concatenation keeps file order");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn merge_to_pcap_rejects_mixed_linktypes() {
        let dir = tmp_dir("mixed");
        let a = dir.join("a.pcap");
        let b = dir.join("b.pcap");
        // Same helper writes linktype 1; forge a second linktype by hand.
        write_pcap(&a, &[(1, 0, 4)]);
        {
            let mut w = RingWriter::create(&b, 105, RingBufferOptions::default()).unwrap();
            w.write(2, 0, 4, &[0; 4]).unwrap();
            w.finish().unwrap();
        }
        let out = dir.join("bad.pcap");
        let err = merge(
            &[a, b],
            &out,
            &MergeOptions { format: WriteFormat::Pcap, chronological: true, comment: None },
        )
        .unwrap_err();
        assert!(err.to_string().contains("different link types"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn split_by_packet_count() {
        let dir = tmp_dir("split-count");
        let input = dir.join("in.pcap");
        let frames: Vec<(u32, u8, usize)> = (0..10).map(|i| (100 + i, i as u8, 8)).collect();
        write_pcap(&input, &frames);

        let files = split(
            &input,
            &dir.join("part.pcap"),
            &SplitOptions { format: WriteFormat::Pcap, mode: SplitMode::Packets(3) },
        )
        .unwrap();
        // 10 packets / 3 → 4 files (3,3,3,1).
        assert_eq!(files.len(), 4);
        let counts: Vec<usize> = files.iter().map(|f| read_all(f).len()).collect();
        assert_eq!(counts, vec![3, 3, 3, 1]);
        // Names are numbered in the prefix's directory.
        assert!(files[0].file_name().unwrap().to_string_lossy().contains("part_00001"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn split_by_time_span() {
        let dir = tmp_dir("split-time");
        let input = dir.join("in.pcap");
        // Packets at t=0,1,2 then 10,11 — a 5s window yields two chunks.
        write_pcap(
            &input,
            &[(0, 1, 4), (1, 2, 4), (2, 3, 4), (10, 4, 4), (11, 5, 4)],
        );
        let files = split(
            &input,
            &dir.join("w.pcap"),
            &SplitOptions { format: WriteFormat::Pcap, mode: SplitMode::Seconds(5) },
        )
        .unwrap();
        let counts: Vec<usize> = files.iter().map(|f| read_all(f).len()).collect();
        assert_eq!(counts, vec![3, 2]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn info_reports_counts_and_span() {
        let dir = tmp_dir("info");
        let input = dir.join("in.pcap");
        write_pcap(&input, &[(100, 1, 10), (105, 2, 20)]);
        let i = info(&input).unwrap();
        assert_eq!(i.format, CaptureFormat::Pcap);
        assert_eq!(i.linktype, 1);
        assert_eq!(i.packets, 2);
        assert_eq!(i.data_bytes, 30);
        assert_eq!(i.first, Some((100, 0)));
        assert_eq!(i.last, Some((105, 0)));
        assert_eq!(i.duration_secs(), Some(5.0));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn round_trip_pcapng_preserves_nanoseconds() {
        let dir = tmp_dir("ns");
        // Split a pcapng and confirm ns timestamps survive the writer.
        let src = dir.join("src.pcapng");
        {
            let mut w = PcapngWriter::create(
                &src,
                SectionMeta::default(),
                &[InterfaceMeta { linktype: 1, ..Default::default() }],
            )
            .unwrap();
            w.write_packet(0, 5, 123_456_789, 4, &[1, 2, 3, 4], None).unwrap();
            w.finish().unwrap();
        }
        let files = split(
            &src,
            &dir.join("out.pcapng"),
            &SplitOptions { format: WriteFormat::PcapNg, mode: SplitMode::Packets(10) },
        )
        .unwrap();
        let f = &read_all(&files[0])[0];
        assert_eq!((f.ts_sec, f.ts_nanos), (5, 123_456_789));
        std::fs::remove_dir_all(dir).ok();
    }
}
