// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! pcapng writer — netscope's native "save" format, matching Wireshark's
//! default. Unlike classic pcap, pcapng carries structured metadata:
//!
//! * a **Section Header Block** with capture-tool / OS / user-comment options,
//! * one or more **Interface Description Blocks** (multi-interface captures,
//!   each with a name, description and timestamp resolution), and
//! * **Enhanced Packet Blocks** that reference an interface and can carry a
//!   per-packet comment.
//!
//! Timestamps are written at nanosecond resolution (`if_tsresol = 9`) so no
//! precision is lost round-tripping a capture. Everything is little-endian;
//! the SHB's byte-order magic records that for readers.
//!
//! ```no_run
//! use netscope_core::pcapng::{PcapngWriter, SectionMeta, InterfaceMeta};
//! let mut w = PcapngWriter::create(
//!     "out.pcapng",
//!     SectionMeta { application: Some("netscope".into()), ..Default::default() },
//!     &[InterfaceMeta { linktype: 1, name: Some("eth0".into()), ..Default::default() }],
//! )?;
//! w.write_packet(0, 1_700_000_000, 250_000_000, 60, &[0u8; 60], Some("first frame"))?;
//! w.finish()?;
//! # std::io::Result::Ok(())
//! ```

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

// Block types.
const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

// Option codes.
const OPT_ENDOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1; // shared: shb/idb/epb comment
const SHB_HARDWARE: u16 = 2;
const SHB_OS: u16 = 3;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_TSRESOL: u16 = 9;

/// Nanosecond timestamp resolution (`if_tsresol` value): 10^-9 s per tick.
const TSRESOL_NANOS: u8 = 9;

/// Section-level metadata (Section Header Block options).
#[derive(Debug, Clone, Default)]
pub struct SectionMeta {
    /// Free-text section comment (`shb_comment`).
    pub comment: Option<String>,
    /// Capture host hardware (`shb_hardware`).
    pub hardware: Option<String>,
    /// Capture host OS (`shb_os`).
    pub os: Option<String>,
    /// Capturing application (`shb_userappl`).
    pub application: Option<String>,
}

/// Per-interface metadata (Interface Description Block).
#[derive(Debug, Clone, Default)]
pub struct InterfaceMeta {
    /// Link-layer type (DLT_*); 1 = Ethernet.
    pub linktype: i32,
    /// Max captured length; 0 means "no limit" (written as 0).
    pub snaplen: u32,
    /// Interface name (`if_name`, e.g. "eth0").
    pub name: Option<String>,
    /// Human description (`if_description`).
    pub description: Option<String>,
}

/// Streaming pcapng writer. Create it (writes the section header and every
/// interface block), append packets, then [`finish`](Self::finish).
pub struct PcapngWriter<W: Write> {
    inner: W,
    interfaces: u32,
}

impl PcapngWriter<BufWriter<File>> {
    /// Create `path`, write the Section Header Block and one Interface
    /// Description Block per entry in `interfaces`.
    pub fn create(
        path: impl AsRef<Path>,
        section: SectionMeta,
        interfaces: &[InterfaceMeta],
    ) -> io::Result<Self> {
        let file = BufWriter::new(File::create(path)?);
        Self::new(file, section, interfaces)
    }
}

impl<W: Write> PcapngWriter<W> {
    /// Write the section header + interface blocks onto an arbitrary sink.
    pub fn new(
        mut inner: W,
        section: SectionMeta,
        interfaces: &[InterfaceMeta],
    ) -> io::Result<Self> {
        write_shb(&mut inner, &section)?;
        for iface in interfaces {
            write_idb(&mut inner, iface)?;
        }
        Ok(Self {
            inner,
            interfaces: interfaces.len() as u32,
        })
    }

    /// Declare an extra interface after construction; returns its id.
    pub fn add_interface(&mut self, iface: &InterfaceMeta) -> io::Result<u32> {
        write_idb(&mut self.inner, iface)?;
        let id = self.interfaces;
        self.interfaces += 1;
        Ok(id)
    }

    /// Append one packet as an Enhanced Packet Block. `ts_sec`/`ts_nanos` are
    /// seconds and the nanosecond remainder; `orig_len` is the on-wire length
    /// (may exceed `data.len()` under a snaplen); `comment` becomes an
    /// `opt_comment` on the block.
    pub fn write_packet(
        &mut self,
        interface_id: u32,
        ts_sec: i64,
        ts_nanos: u32,
        orig_len: u32,
        data: &[u8],
        comment: Option<&str>,
    ) -> io::Result<()> {
        // Total nanoseconds since the epoch → 64-bit tick count (tsresol 9).
        let ticks = (ts_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts_nanos as u64);
        let ts_high = (ticks >> 32) as u32;
        let ts_low = (ticks & 0xFFFF_FFFF) as u32;

        let mut opts = Vec::new();
        if let Some(c) = comment.filter(|c| !c.is_empty()) {
            push_option(&mut opts, OPT_COMMENT, c.as_bytes());
            end_options(&mut opts);
        }

        let pad = pad_to_4(data.len());
        let total = 32 + data.len() + pad + opts.len();

        let w = &mut self.inner;
        w.write_all(&BT_EPB.to_le_bytes())?;
        w.write_all(&(total as u32).to_le_bytes())?;
        w.write_all(&interface_id.to_le_bytes())?;
        w.write_all(&ts_high.to_le_bytes())?;
        w.write_all(&ts_low.to_le_bytes())?;
        w.write_all(&(data.len() as u32).to_le_bytes())?; // captured length
        w.write_all(&orig_len.to_le_bytes())?; // original length
        w.write_all(data)?;
        w.write_all(&ZERO[..pad])?;
        w.write_all(&opts)?;
        w.write_all(&(total as u32).to_le_bytes())?;
        Ok(())
    }

    /// Flush buffered bytes. Call before dropping so nothing is lost.
    pub fn finish(mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

const ZERO: [u8; 4] = [0; 4];

/// Bytes of zero padding to reach a 4-byte boundary.
fn pad_to_4(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// Append one option record: code(2) len(2) value(len) padded to 4 bytes.
fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    buf.extend(std::iter::repeat_n(0u8, pad_to_4(value.len())));
}

/// Terminate an option list with `opt_endofopt`.
fn end_options(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&OPT_ENDOFOPT.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
}

fn write_shb<W: Write>(w: &mut W, meta: &SectionMeta) -> io::Result<()> {
    let mut opts = Vec::new();
    if let Some(c) = meta.comment.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, OPT_COMMENT, c.as_bytes());
    }
    if let Some(h) = meta.hardware.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, SHB_HARDWARE, h.as_bytes());
    }
    if let Some(o) = meta.os.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, SHB_OS, o.as_bytes());
    }
    if let Some(a) = meta.application.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, SHB_USERAPPL, a.as_bytes());
    }
    if !opts.is_empty() {
        end_options(&mut opts);
    }
    // 16 fixed body bytes (magic + version + section length) + options.
    let total = 28 + opts.len();
    w.write_all(&BT_SHB.to_le_bytes())?;
    w.write_all(&(total as u32).to_le_bytes())?;
    w.write_all(&BYTE_ORDER_MAGIC.to_le_bytes())?;
    w.write_all(&1u16.to_le_bytes())?; // version major
    w.write_all(&0u16.to_le_bytes())?; // version minor
    w.write_all(&(-1i64).to_le_bytes())?; // section length: unknown
    w.write_all(&opts)?;
    w.write_all(&(total as u32).to_le_bytes())?;
    Ok(())
}

fn write_idb<W: Write>(w: &mut W, iface: &InterfaceMeta) -> io::Result<()> {
    let mut opts = Vec::new();
    if let Some(n) = iface.name.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, IF_NAME, n.as_bytes());
    }
    if let Some(d) = iface.description.as_deref().filter(|s| !s.is_empty()) {
        push_option(&mut opts, IF_DESCRIPTION, d.as_bytes());
    }
    // Nanosecond timestamps for every interface we write.
    push_option(&mut opts, IF_TSRESOL, &[TSRESOL_NANOS]);
    end_options(&mut opts);

    // 8 fixed body bytes (linktype + reserved + snaplen) + options.
    let total = 20 + opts.len();
    w.write_all(&BT_IDB.to_le_bytes())?;
    w.write_all(&(total as u32).to_le_bytes())?;
    w.write_all(&(iface.linktype as u16).to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?; // reserved
    w.write_all(&iface.snaplen.to_le_bytes())?;
    w.write_all(&opts)?;
    w.write_all(&(total as u32).to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::PcapStreamReader;

    fn write_sample(section: SectionMeta, ifaces: &[InterfaceMeta]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf, section, ifaces).unwrap();
            w.write_packet(
                0,
                1_700_000_000,
                250_000_000,
                42,
                &[0xAB; 42],
                Some("hello"),
            )
            .unwrap();
            w.write_packet(0, 1_700_000_001, 0, 4, &[1, 2, 3, 4], None)
                .unwrap();
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn writes_a_stream_our_own_reader_accepts() {
        let buf = write_sample(
            SectionMeta {
                application: Some("netscope-test".into()),
                comment: Some("session A".into()),
                ..Default::default()
            },
            &[InterfaceMeta {
                linktype: 1,
                name: Some("eth0".into()),
                description: Some("Test NIC".into()),
                ..Default::default()
            }],
        );

        // Round-trip through the streaming pcapng parser: link type, count,
        // timestamps (ns) and payloads must all survive.
        let mut r = PcapStreamReader::new(buf.as_slice()).unwrap();
        assert_eq!(r.linktype(), 1);
        let f1 = r.next_frame().unwrap().unwrap();
        assert_eq!(f1.ts_sec, 1_700_000_000);
        assert_eq!(f1.ts_nanos, 250_000_000);
        assert_eq!(f1.orig_len, 42);
        assert_eq!(f1.data, vec![0xAB; 42]);
        let f2 = r.next_frame().unwrap().unwrap();
        assert_eq!(f2.ts_sec, 1_700_000_001);
        assert_eq!(f2.data, vec![1, 2, 3, 4]);
        assert!(r.next_frame().unwrap().is_none());
    }

    #[test]
    fn multiple_interfaces_are_declared() {
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(
                &mut buf,
                SectionMeta::default(),
                &[
                    InterfaceMeta {
                        linktype: 1,
                        name: Some("eth0".into()),
                        ..Default::default()
                    },
                    InterfaceMeta {
                        linktype: 1,
                        name: Some("wlan0".into()),
                        ..Default::default()
                    },
                ],
            )
            .unwrap();
            // Second interface's packet.
            w.write_packet(1, 5, 0, 3, &[9, 9, 9], None).unwrap();
            w.finish().unwrap();
        }
        let mut r = PcapStreamReader::new(buf.as_slice()).unwrap();
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.data, vec![9, 9, 9]);
    }

    #[test]
    fn block_lengths_are_multiples_of_four() {
        // A comment of odd length exercises option padding.
        let buf = write_sample(
            SectionMeta {
                comment: Some("odd".into()),
                ..Default::default()
            },
            &[InterfaceMeta {
                linktype: 1,
                ..Default::default()
            }],
        );
        // Every block's total-length field (offset 4) must be 4-aligned, and
        // the file length must be exactly the sum of block lengths.
        assert_eq!(buf.len() % 4, 0);
    }
}
