// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MPLS label-stack parsing (EtherType 0x8847 unicast, 0x8848 multicast).
//!
//! MPLS ("Multi-Protocol Label Switching") is how carrier and large enterprise
//! networks forward traffic by short labels instead of IP lookups — the basis of
//! most VPN and traffic-engineering backbones. One or more 4-byte label-stack
//! entries prefix the real packet: a 20-bit label, 3 experimental/traffic-class
//! bits, a 1-bit bottom-of-stack marker, and an 8-bit TTL. We parse the stack so
//! the dispatcher can unwrap it and dissect the inner IP packet, then label the
//! result with the top MPLS label.

/// The parsed MPLS label stack: the outermost (top) label and TTL, how many
/// labels were on the stack, and the byte offset where the inner packet begins.
pub struct MplsStack {
    pub top_label: u32,
    pub top_ttl: u8,
    pub label_count: usize,
    pub inner_offset: usize,
}

/// Walk the label stack until the bottom-of-stack bit is set. Returns `None` on
/// a truncated stack (no bottom-of-stack entry within the payload).
pub fn parse(payload: &[u8]) -> Option<MplsStack> {
    let mut offset = 0;
    let mut count = 0;
    let mut top_label = 0;
    let mut top_ttl = 0;

    loop {
        let entry = payload.get(offset..offset + 4)?;
        let label =
            (u32::from(entry[0]) << 12) | (u32::from(entry[1]) << 4) | (u32::from(entry[2]) >> 4);
        let bottom_of_stack = entry[2] & 0x01 != 0;
        let ttl = entry[3];
        if count == 0 {
            top_label = label;
            top_ttl = ttl;
        }
        count += 1;
        offset += 4;
        if bottom_of_stack {
            return Some(MplsStack {
                top_label,
                top_ttl,
                label_count: count,
                inner_offset: offset,
            });
        }
        // Guard against a runaway/garbage stack.
        if count >= 16 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one MPLS label-stack entry.
    fn entry(label: u32, bottom: bool, ttl: u8) -> [u8; 4] {
        let b0 = (label >> 12) as u8;
        let b1 = (label >> 4) as u8;
        let mut b2 = ((label & 0x0f) << 4) as u8;
        if bottom {
            b2 |= 0x01;
        }
        [b0, b1, b2, ttl]
    }

    #[test]
    fn single_label() {
        let e = entry(16, true, 64);
        let s = parse(&e).unwrap();
        assert_eq!(s.top_label, 16);
        assert_eq!(s.top_ttl, 64);
        assert_eq!(s.label_count, 1);
        assert_eq!(s.inner_offset, 4);
    }

    #[test]
    fn stacked_labels() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry(100, false, 64)); // outer
        buf.extend_from_slice(&entry(200, true, 64)); // inner / bottom
        let s = parse(&buf).unwrap();
        assert_eq!(s.top_label, 100);
        assert_eq!(s.label_count, 2);
        assert_eq!(s.inner_offset, 8);
    }

    #[test]
    fn truncated_stack_is_none() {
        // No bottom-of-stack bit ever set, and too short for another entry.
        let e = entry(16, false, 64);
        assert!(parse(&e).is_none());
    }
}
