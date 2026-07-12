//! Packet streaming & lazy parse — open big pcaps without loading or parsing
//! them up front (ROADMAP §2.2).
//!
//! [`LazyCapture`] memory-maps a classic pcap file and scans only the 16-byte
//! record headers to build a packet index (offset + timestamp + lengths).
//! Nothing is copied and nothing is dissected until a packet is actually
//! looked at; dissected packets go into a bounded LRU cache so scrolling back
//! and forth stays cheap. A 1 GB capture therefore costs ~24 bytes of index
//! per packet instead of 2–3 GB of parsed `Packet`s.
//!
//! ```no_run
//! use netscope_core::stream::LazyCapture;
//!
//! let cap = LazyCapture::open("big.pcap")?;
//! println!("{} packets", cap.len());
//! let pkt = cap.packet(1_000_000).unwrap();   // parsed on first access
//! # anyhow::Ok(())
//! ```
//!
//! Only the classic pcap format (`.pcap`) is mapped; pcapng files return a
//! clear error so callers can fall back to the streaming
//! [`CaptureEngine`](crate::capture::CaptureEngine) path, which handles them
//! through libpcap.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::dissectors;
use crate::models::Packet;

/// Magic numbers for the classic pcap global header.
const MAGIC_US: u32 = 0xa1b2_c3d4; // microsecond timestamps, writer-endian
const MAGIC_NS: u32 = 0xa1b2_3c4d; // nanosecond timestamps, writer-endian
const MAGIC_US_SWAPPED: u32 = 0xd4c3_b2a1;
const MAGIC_NS_SWAPPED: u32 = 0x4d3c_b2a1;
/// pcapng section header block type — recognised only to give a good error.
const PCAPNG_MAGIC: u32 = 0x0a0d_0d0a;

/// Records longer than this are treated as corruption, not data. Real
/// snaplens top out at 256 KiB (D-Bus captures); 64 MiB is generous.
const MAX_SANE_CAPLEN: u32 = 64 * 1024 * 1024;

/// Dissected packets kept hot. At ~1.6 KB per average packet this bounds the
/// cache near 6 MB — enough to cover a UI viewport plus generous scrollback.
const CACHE_CAPACITY: usize = 4096;

/// Location and metadata of one packet inside the mapped file. 24 bytes per
/// packet, the only per-packet cost of opening a capture.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// Offset of the packet *data* (past the record header).
    offset: u64,
    /// Seconds since the Unix epoch.
    ts_sec: u32,
    /// Sub-second part, in micro- or nanoseconds depending on the file magic.
    ts_frac: u32,
    /// Bytes stored in the file for this packet.
    caplen: u32,
    /// Original on-wire length.
    orig_len: u32,
}

/// A memory-mapped pcap with a packet index and on-demand dissection.
pub struct LazyCapture {
    map: memmap2::Mmap,
    index: Vec<IndexEntry>,
    linktype: i32,
    nanos: bool,
    cache: Mutex<LruCache>,
}

impl std::fmt::Debug for LazyCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyCapture")
            .field("packets", &self.index.len())
            .field("linktype", &self.linktype)
            .field("nanos", &self.nanos)
            .finish_non_exhaustive()
    }
}

impl LazyCapture {
    /// Map `path` and index its packets. Fails on pcapng or a corrupt global
    /// header; a file that ends mid-record is indexed up to the last complete
    /// packet, matching what other readers do with truncated captures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .with_context(|| format!("cannot open '{}'", path.display()))?;
        // SAFETY: we map the file read-only and never hand out mutable access.
        // If another process truncates the file while mapped, reads could
        // fault — the standard, accepted trade-off of every mmap-based reader
        // (tcpdump, Wireshark). netscope itself never rewrites a pcap in place.
        let map = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("cannot memory-map '{}'", path.display()))?;
        Self::from_mmap(map)
    }

    fn from_mmap(map: memmap2::Mmap) -> Result<Self> {
        let bytes: &[u8] = &map;
        if bytes.len() < 24 {
            anyhow::bail!("not a pcap file: shorter than the 24-byte global header");
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let (swapped, nanos) = match magic {
            MAGIC_US => (false, false),
            MAGIC_NS => (false, true),
            MAGIC_US_SWAPPED => (true, false),
            MAGIC_NS_SWAPPED => (true, true),
            PCAPNG_MAGIC => anyhow::bail!(
                "pcapng format is not supported by the memory-mapped reader — \
                 falling back to the streaming reader handles it"
            ),
            other => anyhow::bail!("not a pcap file (magic 0x{other:08x})"),
        };
        let read_u32 = |off: usize| -> u32 {
            let raw = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            if swapped {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            }
        };
        let linktype = read_u32(20) as i32;

        // Index pass: walk the 16-byte record headers, never touching payload.
        let mut index = Vec::new();
        let mut off: usize = 24;
        while off + 16 <= bytes.len() {
            let ts_sec = read_u32(off);
            let ts_frac = read_u32(off + 4);
            let caplen = read_u32(off + 8);
            let orig_len = read_u32(off + 12);
            if caplen > MAX_SANE_CAPLEN {
                break; // corrupt length field — stop at the last good packet
            }
            let data_start = off + 16;
            let data_end = match data_start.checked_add(caplen as usize) {
                Some(e) if e <= bytes.len() => e,
                _ => break, // truncated final record
            };
            index.push(IndexEntry {
                offset: data_start as u64,
                ts_sec,
                ts_frac,
                caplen,
                orig_len,
            });
            off = data_end;
        }

        Ok(Self {
            map,
            index,
            linktype,
            nanos,
            cache: Mutex::new(LruCache::new(CACHE_CAPACITY)),
        })
    }

    /// Number of indexed packets.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The capture's link-layer type (DLT_*), which decides how frames are
    /// dissected (Ethernet vs. 802.11/radiotap).
    pub fn linktype(&self) -> i32 {
        self.linktype
    }

    /// Raw captured bytes of packet `i` — a zero-copy slice into the map.
    pub fn raw(&self, i: usize) -> Option<&[u8]> {
        let e = self.index.get(i)?;
        let start = e.offset as usize;
        Some(&self.map[start..start + e.caplen as usize])
    }

    /// Timestamp of packet `i` without dissecting it.
    pub fn timestamp(&self, i: usize) -> Option<DateTime<Utc>> {
        let e = self.index.get(i)?;
        Some(self.entry_time(e))
    }

    fn entry_time(&self, e: &IndexEntry) -> DateTime<Utc> {
        let nanos = if self.nanos {
            e.ts_frac
        } else {
            e.ts_frac.saturating_mul(1000)
        };
        DateTime::from_timestamp(e.ts_sec as i64, nanos).unwrap_or_default()
    }

    /// Packet `i`, dissected on first access and then served from the LRU
    /// cache. Returns `None` past the end.
    pub fn packet(&self, i: usize) -> Option<Packet> {
        if let Some(hit) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(i) {
            return Some(hit);
        }
        let pkt = self.parse(i)?;
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(i, pkt.clone());
        Some(pkt)
    }

    /// A contiguous page of packets — the shape UI viewports ask for.
    /// Uncached entries are dissected in parallel with rayon, so paging
    /// through a cold million-packet file uses every core.
    pub fn packets_range(&self, start: usize, count: usize) -> Vec<Packet> {
        use rayon::prelude::*;
        let end = start.saturating_add(count).min(self.index.len());
        if start >= end {
            return Vec::new();
        }
        // Serve what the cache has, note what it doesn't.
        let mut out: Vec<Option<Packet>> = {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            (start..end).map(|i| cache.get(i)).collect()
        };
        let missing: Vec<usize> = (start..end).filter(|i| out[i - start].is_none()).collect();
        let parsed: Vec<(usize, Packet)> = missing
            .par_iter()
            .filter_map(|&i| self.parse(i).map(|p| (i, p)))
            .collect();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            for (i, pkt) in &parsed {
                cache.put(*i, pkt.clone());
            }
        }
        for (i, pkt) in parsed {
            out[i - start] = Some(pkt);
        }
        out.into_iter().flatten().collect()
    }

    /// Index of the first packet at or after `ts` — binary search over the
    /// (monotonically recorded) timestamps. Equal to [`len`](Self::len) when
    /// every packet is earlier.
    pub fn find_by_time(&self, ts: DateTime<Utc>) -> usize {
        self.index.partition_point(|e| self.entry_time(e) < ts)
    }

    /// Dissect packet `i` from the mapped bytes (no cache involvement).
    fn parse(&self, i: usize) -> Option<Packet> {
        let e = *self.index.get(i)?;
        let data = self.raw(i)?;
        let d = dissectors::dissect_linktype(data, self.linktype);
        Some(Packet {
            timestamp: self.entry_time(&e),
            src_addr: d.src_addr,
            dst_addr: d.dst_addr,
            src_port: d.src_port,
            dst_port: d.dst_port,
            protocol: d.protocol,
            length: e.orig_len as usize,
            summary: d.summary,
            data: bytes::Bytes::copy_from_slice(data),
        })
    }
}

/// Exact LRU keyed by packet index. Lookups are O(1); evictions scan the
/// (bounded) map for the oldest stamp, which is trivial next to dissection
/// cost and keeps the implementation free of unsafe pointer juggling.
struct LruCache {
    cap: usize,
    clock: u64,
    map: HashMap<usize, (u64, Packet)>,
}

impl LruCache {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            clock: 0,
            map: HashMap::with_capacity(cap.max(1)),
        }
    }

    fn get(&mut self, key: usize) -> Option<Packet> {
        self.clock += 1;
        let clock = self.clock;
        let (stamp, pkt) = self.map.get_mut(&key)?;
        *stamp = clock;
        Some(pkt.clone())
    }

    fn put(&mut self, key: usize, pkt: Packet) {
        self.clock += 1;
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            if let Some(&oldest) = self
                .map
                .iter()
                .min_by_key(|(_, (stamp, _))| *stamp)
                .map(|(k, _)| k)
            {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(key, (self.clock, pkt));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{build_dns_query, build_tcp_packet, build_udp_packet};
    use crate::models::Protocol;

    /// Build an in-memory classic pcap from frames, in either endianness.
    fn build_pcap(frames: &[(u32, u32, &[u8])], swapped: bool, nanos: bool) -> Vec<u8> {
        let w32 = |v: u32| -> [u8; 4] {
            if swapped {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let magic = if nanos { MAGIC_NS } else { MAGIC_US };
        let w16 = |v: u16| -> [u8; 2] {
            if swapped {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&w32(magic));
        buf.extend_from_slice(&w16(2)); // version major
        buf.extend_from_slice(&w16(4)); // version minor
        buf.extend_from_slice(&w32(0)); // thiszone
        buf.extend_from_slice(&w32(0)); // sigfigs
        buf.extend_from_slice(&w32(65535)); // snaplen
        buf.extend_from_slice(&w32(1)); // linktype: Ethernet
        for (sec, frac, data) in frames {
            buf.extend_from_slice(&w32(*sec));
            buf.extend_from_slice(&w32(*frac));
            buf.extend_from_slice(&w32(data.len() as u32));
            buf.extend_from_slice(&w32(data.len() as u32));
            buf.extend_from_slice(data);
        }
        buf
    }

    fn open_bytes(bytes: &[u8]) -> Result<LazyCapture> {
        let path = std::env::temp_dir().join(format!(
            "netscope-stream-{}-{}.pcap",
            std::process::id(),
            // Unique per call so parallel tests don't collide.
            {
                use std::sync::atomic::{AtomicU64, Ordering};
                static N: AtomicU64 = AtomicU64::new(0);
                N.fetch_add(1, Ordering::Relaxed)
            }
        ));
        std::fs::write(&path, bytes).unwrap();
        LazyCapture::open(&path)
    }

    fn sample_frames() -> Vec<Vec<u8>> {
        vec![
            build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                12345,
                80,
                false,
                true,
                false,
                false,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
            build_udp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                54321,
                53,
                &build_dns_query("example.com", 7),
            ),
            build_tcp_packet(
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                80,
                12345,
                false,
                false,
                true,
                false,
                &[],
            ),
        ]
    }

    #[test]
    fn indexes_and_lazily_parses() {
        let frames = sample_frames();
        let records: Vec<(u32, u32, &[u8])> = frames
            .iter()
            .enumerate()
            .map(|(i, f)| (1_700_000_000 + i as u32, 250_000, f.as_slice()))
            .collect();
        let cap = open_bytes(&build_pcap(&records, false, false)).unwrap();

        assert_eq!(cap.len(), 3);
        assert_eq!(cap.linktype(), 1);
        // Raw access is exact bytes:
        assert_eq!(cap.raw(1).unwrap(), frames[1].as_slice());
        // Parse on access:
        let p0 = cap.packet(0).unwrap();
        assert_eq!(p0.protocol, Protocol::Http);
        assert_eq!(p0.length, frames[0].len());
        let p1 = cap.packet(1).unwrap();
        assert_eq!(p1.protocol, Protocol::Dns);
        // Microsecond fraction becomes 250 ms:
        assert_eq!(p1.timestamp.timestamp_subsec_millis(), 250);
        // Past the end:
        assert!(cap.packet(3).is_none());
        assert!(cap.raw(3).is_none());
    }

    #[test]
    fn cached_packet_is_served_again() {
        let frames = sample_frames();
        let records: Vec<(u32, u32, &[u8])> = frames.iter().map(|f| (1, 0, f.as_slice())).collect();
        let cap = open_bytes(&build_pcap(&records, false, false)).unwrap();
        let a = cap.packet(2).unwrap();
        let b = cap.packet(2).unwrap();
        assert_eq!(a.summary, b.summary);
        assert_eq!(a.protocol, b.protocol);
    }

    #[test]
    fn swapped_endianness_and_nanoseconds() {
        let frames = sample_frames();
        // Big-endian writer:
        let records: Vec<(u32, u32, &[u8])> =
            frames.iter().map(|f| (100, 0, f.as_slice())).collect();
        let cap = open_bytes(&build_pcap(&records, true, false)).unwrap();
        assert_eq!(cap.len(), 3);
        assert_eq!(cap.packet(0).unwrap().protocol, Protocol::Http);

        // Nanosecond magic: fraction is taken as ns, not scaled.
        let one = [(5u32, 123_456_789u32, frames[0].as_slice())];
        let cap = open_bytes(&build_pcap(&one, false, true)).unwrap();
        assert_eq!(
            cap.packet(0).unwrap().timestamp.timestamp_subsec_nanos(),
            123_456_789
        );
    }

    #[test]
    fn truncated_final_record_is_dropped() {
        let frames = sample_frames();
        let records: Vec<(u32, u32, &[u8])> = frames.iter().map(|f| (1, 0, f.as_slice())).collect();
        let mut bytes = build_pcap(&records, false, false);
        // Chop the last packet's payload mid-way:
        let cut = bytes.len() - 10;
        bytes.truncate(cut);
        let cap = open_bytes(&bytes).unwrap();
        assert_eq!(cap.len(), 2);
    }

    #[test]
    fn rejects_pcapng_and_garbage() {
        let mut ng = vec![0u8; 32];
        ng[..4].copy_from_slice(&PCAPNG_MAGIC.to_le_bytes());
        let err = open_bytes(&ng).unwrap_err().to_string();
        assert!(err.contains("pcapng"), "{err}");

        let err = open_bytes(&[0xffu8; 64]).unwrap_err().to_string();
        assert!(err.contains("magic"), "{err}");

        assert!(open_bytes(&[1, 2, 3]).is_err());
    }

    #[test]
    fn empty_capture_has_no_packets() {
        let cap = open_bytes(&build_pcap(&[], false, false)).unwrap();
        assert!(cap.is_empty());
        assert_eq!(cap.find_by_time(Utc::now()), 0);
    }

    #[test]
    fn find_by_time_binary_search() {
        let frames = sample_frames();
        let records: Vec<(u32, u32, &[u8])> = frames
            .iter()
            .enumerate()
            .map(|(i, f)| (100 + (i as u32) * 10, 0, f.as_slice()))
            .collect(); // t = 100, 110, 120
        let cap = open_bytes(&build_pcap(&records, false, false)).unwrap();

        let at = |s: i64| DateTime::from_timestamp(s, 0).unwrap();
        assert_eq!(cap.find_by_time(at(50)), 0);
        assert_eq!(cap.find_by_time(at(105)), 1);
        assert_eq!(cap.find_by_time(at(110)), 1);
        assert_eq!(cap.find_by_time(at(111)), 2);
        assert_eq!(cap.find_by_time(at(999)), 3);
    }

    #[test]
    fn packets_range_pages_and_clamps() {
        let frames = sample_frames();
        let records: Vec<(u32, u32, &[u8])> = frames.iter().map(|f| (1, 0, f.as_slice())).collect();
        let cap = open_bytes(&build_pcap(&records, false, false)).unwrap();

        let page = cap.packets_range(1, 10);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].protocol, Protocol::Dns);
        // Second call is served from cache and must agree:
        let again = cap.packets_range(1, 10);
        assert_eq!(again.len(), 2);
        assert_eq!(again[0].summary, page[0].summary);
        // Out-of-range start:
        assert!(cap.packets_range(99, 5).is_empty());
    }

    #[test]
    fn lru_evicts_oldest_and_refreshes_on_get() {
        let mk = |n: usize| Packet {
            timestamp: Default::default(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Tcp,
            length: n,
            summary: format!("p{n}"),
            data: bytes::Bytes::new(),
        };
        let mut lru = LruCache::new(2);
        lru.put(1, mk(1));
        lru.put(2, mk(2));
        // Touch 1 so 2 becomes the LRU victim.
        assert!(lru.get(1).is_some());
        lru.put(3, mk(3));
        assert!(lru.get(2).is_none(), "2 should have been evicted");
        assert!(lru.get(1).is_some());
        assert!(lru.get(3).is_some());
    }
}
