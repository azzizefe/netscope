// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Minimal radiotap header parser.
//!
//! Radiotap is the pseudo-header monitor-mode captures prepend to each 802.11
//! frame to carry radio metadata (signal, channel, rate…). We parse the header
//! length (needed to reach the real 802.11 frame) and best-effort extract the
//! signal strength and channel, which are the fields analysts actually read.
//!
//! Reference: <https://www.radiotap.org/>

/// Parsed radiotap metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Radiotap {
    /// Total length of the radiotap header — the offset to the 802.11 frame.
    pub header_len: usize,
    /// dBm antenna signal, if present (e.g. -45).
    pub signal_dbm: Option<i8>,
    /// Channel frequency in MHz, if present (e.g. 2437).
    pub channel_mhz: Option<u16>,
}

const PRESENT_EXT: u32 = 0x8000_0000;

/// Parse a radiotap header. Returns `None` if the buffer isn't a plausible
/// radiotap header (wrong version, truncated, or a bogus length).
pub fn parse(data: &[u8]) -> Option<Radiotap> {
    // Header: version(1)=0, pad(1), len(2, LE), present(4, LE)…
    if data.len() < 8 || data[0] != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if !(8..=data.len()).contains(&header_len) {
        return None;
    }

    // Walk the present bitmaps: each is 4 bytes; the top bit means another
    // bitmap word follows. Fields begin after the last present word.
    let first_present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut off = 8;
    let mut more = first_present & PRESENT_EXT != 0;
    while more {
        if off + 4 > header_len {
            break;
        }
        let word = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        more = word & PRESENT_EXT != 0;
    }

    let mut rt = Radiotap {
        header_len,
        signal_dbm: None,
        channel_mhz: None,
    };

    // Fields follow, in bit order, each aligned to its natural boundary
    // (relative to the start of the header). We only need up through the
    // signal field (bit 5); if anything runs past the header we stop.
    let mut p = off;
    let field = |size: usize, align: usize, p: &mut usize| -> Option<usize> {
        let start = (*p + align - 1) & !(align - 1);
        if start + size > header_len {
            return None;
        }
        *p = start + size;
        Some(start)
    };

    // bit 0: TSFT (u64, align 8)
    if first_present & (1 << 0) != 0 && field(8, 8, &mut p).is_none() {
        return Some(rt);
    }
    // bit 1: Flags (u8)
    if first_present & (1 << 1) != 0 && field(1, 1, &mut p).is_none() {
        return Some(rt);
    }
    // bit 2: Rate (u8)
    if first_present & (1 << 2) != 0 && field(1, 1, &mut p).is_none() {
        return Some(rt);
    }
    // bit 3: Channel (u16 freq + u16 flags, align 2)
    if first_present & (1 << 3) != 0 {
        match field(4, 2, &mut p) {
            Some(start) => {
                rt.channel_mhz = Some(u16::from_le_bytes([data[start], data[start + 1]]))
            }
            None => return Some(rt),
        }
    }
    // bit 4: FHSS (u16, align 2)
    if first_present & (1 << 4) != 0 && field(2, 2, &mut p).is_none() {
        return Some(rt);
    }
    // bit 5: dBm Antenna Signal (i8)
    if first_present & (1 << 5) != 0 {
        if let Some(start) = field(1, 1, &mut p) {
            rt.signal_dbm = Some(data[start] as i8);
        }
    }

    Some(rt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_length_and_fields() {
        // present = Flags|Rate|Channel|Signal => bits 1,2,3,5 = 0b101110 = 0x2E
        // Field layout from offset 8 (Flags/Rate are 1-aligned, Channel is
        // 2-aligned and offset 10 is already even, so no padding is needed):
        //   Flags@8, Rate@9, Channel@10..14, Signal@14  → header_len = 15
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&[0x00, 0x00, 0x0f, 0x00]); // ver, pad, len=15
        hdr.extend_from_slice(&[0x2e, 0x00, 0x00, 0x00]); // present
        hdr.push(0x00); // Flags @8
        hdr.push(0x02); // Rate  @9
        hdr.extend_from_slice(&[0x6c, 0x09]); // Channel freq 2412 @10..12
        hdr.extend_from_slice(&[0x00, 0x00]); // Channel flags @12..14
        hdr.push((-42i8) as u8); // Signal @14

        let rt = parse(&hdr).unwrap();
        assert_eq!(rt.header_len, 15);
        assert_eq!(rt.channel_mhz, Some(2412));
        assert_eq!(rt.signal_dbm, Some(-42));
    }

    #[test]
    fn rejects_non_radiotap() {
        assert!(parse(&[0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0]).is_none()); // version != 0
        assert!(parse(&[0x00, 0x00]).is_none()); // too short
        assert!(parse(&[0x00, 0x00, 0xff, 0x00, 0, 0, 0, 0]).is_none()); // len > buffer
    }

    #[test]
    fn header_len_only_when_no_fields() {
        // present = 0 → just the 8-byte header, no fields to read.
        let hdr = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let rt = parse(&hdr).unwrap();
        assert_eq!(rt.header_len, 8);
        assert_eq!(rt.signal_dbm, None);
        assert_eq!(rt.channel_mhz, None);
    }
}
