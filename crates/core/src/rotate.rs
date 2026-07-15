// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Ring-buffer capture files — Wireshark's `-b` option for netscope.
//!
//! [`RingWriter`] writes classic pcap files and switches to a new file when
//! the current one exceeds a size or age limit, optionally deleting the
//! oldest files so the set never grows past `files` members. With no
//! rotation limits it degrades to a plain single-file pcap writer, so the
//! capture engine uses it for every live save.
//!
//! Rotated files are named Wireshark-style — `base_00001_20260713142530.pcap`
//! — so a set sorts chronologically in any file browser; a non-rotating
//! writer keeps the exact path it was given.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Rotation policy for a capture-file ring buffer. At least one of
/// `filesize_kb` / `duration_secs` must be set for rotation to happen;
/// `files` alone is rejected (there would be no trigger to ever rotate).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RingBufferOptions {
    /// Switch to the next file once the current one would exceed this many
    /// kilobytes (Wireshark's `-b filesize:NUM` unit).
    pub filesize_kb: Option<u64>,
    /// Switch to the next file after this many seconds.
    pub duration_secs: Option<u64>,
    /// Keep at most this many files, deleting the oldest on rotation.
    pub files: Option<usize>,
}

impl RingBufferOptions {
    /// True when a rotation trigger (size or duration) is configured.
    pub fn rotates(&self) -> bool {
        self.filesize_kb.is_some() || self.duration_secs.is_some()
    }
}

/// Classic pcap writer with optional ring-buffer rotation.
pub struct RingWriter {
    /// The path the user asked for; rotated names derive from it.
    base: PathBuf,
    opts: RingBufferOptions,
    linktype: i32,
    file: BufWriter<File>,
    /// Bytes written to the current file (header + records).
    written: u64,
    /// Records in the current file — a file always accepts at least one
    /// packet, so an over-limit single packet can't rotate forever.
    records: u64,
    opened_at: Instant,
    /// Next rotation serial (Wireshark counts from 1).
    serial: u32,
    /// Paths written so far, oldest first, for pruning.
    created: VecDeque<PathBuf>,
}

const PCAP_MAGIC_US: u32 = 0xa1b2_c3d4;
const PCAP_SNAPLEN: u32 = 65_535;
const RECORD_HEADER: u64 = 16;

impl RingWriter {
    /// Open the first capture file. `linktype` is the capture's DLT, written
    /// into every file header.
    pub fn create(
        path: impl AsRef<Path>,
        linktype: i32,
        opts: RingBufferOptions,
    ) -> io::Result<Self> {
        if !opts.rotates() && opts.files.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ring buffer needs a filesize or duration limit to rotate on \
                 (a file count alone never triggers rotation)",
            ));
        }
        let base = path.as_ref().to_path_buf();
        let first = if opts.rotates() {
            Self::numbered_path(&base, 1)
        } else {
            base.clone()
        };
        let (file, written) = Self::open_file(&first, linktype)?;
        let mut created = VecDeque::new();
        created.push_back(first);
        Ok(Self {
            base,
            opts,
            linktype,
            file,
            written,
            records: 0,
            opened_at: Instant::now(),
            serial: 1,
            created,
        })
    }

    /// Write one packet record, rotating first if a limit would be crossed.
    pub fn write(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        orig_len: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if self.should_rotate(data.len() as u64) {
            self.rotate()?;
        }
        self.file.write_all(&ts_sec.to_le_bytes())?;
        self.file.write_all(&ts_usec.to_le_bytes())?;
        self.file.write_all(&(data.len() as u32).to_le_bytes())?;
        self.file.write_all(&orig_len.to_le_bytes())?;
        self.file.write_all(data)?;
        self.written += RECORD_HEADER + data.len() as u64;
        self.records += 1;
        Ok(())
    }

    /// Flush the current file. Call before dropping so a clean stop never
    /// loses buffered records.
    pub fn finish(mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// Paths written so far, oldest first (pruned files removed).
    pub fn files_written(&self) -> Vec<PathBuf> {
        self.created.iter().cloned().collect()
    }

    fn should_rotate(&self, next_data: u64) -> bool {
        if !self.opts.rotates() || self.records == 0 {
            return false;
        }
        if let Some(kb) = self.opts.filesize_kb {
            if self.written + RECORD_HEADER + next_data > kb.max(1) * 1024 {
                return true;
            }
        }
        if let Some(secs) = self.opts.duration_secs {
            if self.opened_at.elapsed().as_secs() >= secs.max(1) {
                return true;
            }
        }
        false
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.serial += 1;
        let next = Self::numbered_path(&self.base, self.serial);
        let (file, written) = Self::open_file(&next, self.linktype)?;
        self.file = file;
        self.written = written;
        self.records = 0;
        self.opened_at = Instant::now();
        self.created.push_back(next);
        if let Some(max) = self.opts.files {
            while self.created.len() > max.max(1) {
                if let Some(old) = self.created.pop_front() {
                    // Best-effort: a vanished file must not kill the capture.
                    let _ = std::fs::remove_file(old);
                }
            }
        }
        Ok(())
    }

    /// `base.pcap` + serial 3 → `base_00003_20260713142530.pcap`.
    fn numbered_path(base: &Path, serial: u32) -> PathBuf {
        let stem = base
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "capture".into());
        let ext = base
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_else(|| ".pcap".into());
        let stamp = chrono::Local::now().format("%Y%m%d%H%M%S");
        base.with_file_name(format!("{stem}_{serial:05}_{stamp}{ext}"))
    }

    fn open_file(path: &Path, linktype: i32) -> io::Result<(BufWriter<File>, u64)> {
        let mut file = BufWriter::new(File::create(path)?);
        // Classic pcap global header, little-endian, microsecond timestamps.
        file.write_all(&PCAP_MAGIC_US.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?; // version major
        file.write_all(&4u16.to_le_bytes())?; // version minor
        file.write_all(&0i32.to_le_bytes())?; // thiszone (UTC)
        file.write_all(&0u32.to_le_bytes())?; // sigfigs
        file.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
        file.write_all(&(linktype as u32).to_le_bytes())?;
        Ok((file, 24))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netscope-ring-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pcap_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn plain_writer_uses_exact_path_and_valid_header() {
        let dir = temp_dir("plain");
        let path = dir.join("out.pcap");
        let mut w = RingWriter::create(&path, 1, RingBufferOptions::default()).unwrap();
        w.write(1_700_000_000, 0, 60, &[0u8; 60]).unwrap();
        w.finish().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 24 + 16 + 60);
        assert_eq!(&bytes[0..4], &PCAP_MAGIC_US.to_le_bytes());
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 1);
        // Record header: caplen 60, orig_len 60.
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 60);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rotates_on_filesize_and_prunes_oldest() {
        let dir = temp_dir("size");
        let path = dir.join("ring.pcap");
        // 1 kB per file → header (24) + a few 200-byte records each.
        let opts = RingBufferOptions {
            filesize_kb: Some(1),
            duration_secs: None,
            files: Some(2),
        };
        let mut w = RingWriter::create(&path, 1, opts).unwrap();
        for i in 0..20 {
            w.write(1_700_000_000 + i, 0, 200, &[0u8; 200]).unwrap();
        }
        let kept = w.files_written();
        w.finish().unwrap();

        // 20 × 216 bytes ≈ 4.3 kB of records → several rotations; only the
        // last two files survive.
        assert_eq!(kept.len(), 2, "ring must keep exactly `files` members");
        let on_disk = pcap_files(&dir);
        assert_eq!(
            on_disk.len(),
            2,
            "pruned files must be deleted: {on_disk:?}"
        );
        for f in &on_disk {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                name.starts_with("ring_") && name.ends_with(".pcap"),
                "{name}"
            );
            let bytes = std::fs::read(f).unwrap();
            assert_eq!(&bytes[0..4], &PCAP_MAGIC_US.to_le_bytes());
            assert!(bytes.len() > 24, "rotated file must hold records");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn oversized_single_packet_still_lands_in_a_file() {
        let dir = temp_dir("big");
        let opts = RingBufferOptions {
            filesize_kb: Some(1),
            duration_secs: None,
            files: None,
        };
        let mut w = RingWriter::create(dir.join("big.pcap"), 1, opts).unwrap();
        // 4 kB packet in a 1 kB ring: each file takes exactly one record
        // instead of rotating forever.
        w.write(0, 0, 4096, &[0u8; 4096]).unwrap();
        w.write(1, 0, 4096, &[0u8; 4096]).unwrap();
        assert_eq!(w.files_written().len(), 2);
        w.finish().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_limit_alone_is_rejected() {
        let opts = RingBufferOptions {
            filesize_kb: None,
            duration_secs: None,
            files: Some(5),
        };
        let err = RingWriter::create(std::env::temp_dir().join("x.pcap"), 1, opts)
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
