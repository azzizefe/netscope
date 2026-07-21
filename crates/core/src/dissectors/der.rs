// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Reading DER and BER — the tag-length-value encoding under half the
//! security protocols on a network.
//!
//! Kerberos, LDAP, SNMP, OCSP, certificate management and the whole X.509
//! family are all encoded this way: a tag byte, a length, and a value that may
//! itself be a nest of the same thing. Nothing here knows about any of those
//! protocols — this is only the encoding.
//!
//! ## Why this module exists
//!
//! Three copies of the length rule had grown up independently, in
//! `kerberos.rs`, `snmp.rs` and `ldap.rs`, and OCSP was about to add a fourth.
//! The rule has a sharp edge — the long form encodes *the number of length
//! bytes* in the low seven bits, and a zero there means indefinite length,
//! which DER forbids — and copies of a rule with a sharp edge drift apart.
//! That is the same reasoning that put the IPv6 extension-header length in one
//! place; see `ip::ext_header_len`.
//!
//! ## The rule that matters when reading a field out of a structure
//!
//! Fields are found by **walking** the structure, never by scanning for the
//! bytes of the value wanted. In every one of these protocols the fields that
//! precede the interesting one encode identically to it, so a scan returns
//! whichever came first — a protocol version rather than an error code, in the
//! case that first made this a rule.

/// One tag-length-value, and how much of the input it occupied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    /// The identifier octet, including its class and constructed bits.
    pub tag: u8,
    /// The contents, excluding tag and length.
    pub value: &'a [u8],
    /// Tag plus length header plus value — where the next TLV begins.
    pub total: usize,
}

impl Tlv<'_> {
    /// Whether the tag has the constructed bit, meaning the value is itself a
    /// sequence of TLVs rather than a primitive.
    pub fn is_constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// The context-specific tag number, for the `[n]` fields these protocols
    /// use to mark optional members. `None` when the tag is not
    /// context-specific.
    pub fn context_tag(&self) -> Option<u8> {
        (self.tag & 0xC0 == 0x80).then_some(self.tag & 0x1F)
    }
}

/// Decode a length field, returning the length and how many bytes the length
/// field itself occupied (including its leading octet).
///
/// The long form puts the *count of length bytes* in the low seven bits, not
/// the length. A count of zero means indefinite length, which BER allows and
/// DER does not, and which nothing here can act on — so it is rejected rather
/// than read as a zero-length value.
pub(crate) fn length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7F) as usize;
    // Zero is indefinite length; beyond four is longer than any packet.
    if count == 0 || count > 4 || data.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..1 + count] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + count))
}

/// Read the TLV at the start of `data`.
pub(crate) fn read(data: &[u8]) -> Option<Tlv<'_>> {
    let tag = *data.first()?;
    let (len, header) = length(data.get(1..)?)?;
    let start = 1 + header;
    let value = data.get(start..start + len)?;
    Some(Tlv {
        tag,
        value,
        total: start + len,
    })
}

/// Step over the TLV at `at`, returning where the next one begins.
pub(crate) fn skip(data: &[u8], at: usize) -> Option<usize> {
    Some(at + read(data.get(at..)?)?.total)
}

/// Walk a sequence of TLVs, yielding each in turn.
///
/// Stops at the first malformed entry rather than guessing, because a
/// misread length desynchronises everything after it — a walk that keeps
/// going past a bad length is reading the wrong bytes, not recovering.
pub(crate) fn children(value: &[u8]) -> impl Iterator<Item = Tlv<'_>> {
    let mut rest = value;
    std::iter::from_fn(move || {
        let tlv = read(rest)?;
        rest = &rest[tlv.total..];
        Some(tlv)
    })
}

/// Find the first child with the given tag, one level down.
pub(crate) fn find(value: &[u8], tag: u8) -> Option<Tlv<'_>> {
    children(value).find(|t| t.tag == tag)
}

/// Read a non-negative INTEGER or ENUMERATED value.
///
/// Values wider than eight bytes, and negative ones, are rejected rather than
/// truncated — a status code that does not fit is not a status code.
pub(crate) fn uint(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 9 {
        return None;
    }
    // DER pads with a leading zero when the high bit would otherwise make the
    // value negative; anything else with the high bit set really is negative.
    let bytes = match value {
        [0, rest @ ..] => rest,
        [first, ..] if first & 0x80 != 0 => return None,
        all => all,
    };
    if bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLV.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if value.len() < 0x80 {
            v.push(value.len() as u8);
        } else {
            let len = value.len();
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let used = &bytes[first..];
            v.push(0x80 | used.len() as u8);
            v.extend_from_slice(used);
        }
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn the_short_form_length_is_the_byte_itself() {
        assert_eq!(length(&[0x05]), Some((5, 1)));
        assert_eq!(length(&[0x00]), Some((0, 1)));
        assert_eq!(length(&[0x7F]), Some((127, 1)));
    }

    /// The long form encodes the *count of length bytes*, not the length. Read
    /// as a length, 0x82 would mean 130 rather than "two bytes follow".
    #[test]
    fn the_long_form_encodes_a_count_not_a_length() {
        assert_eq!(length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(length(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(length(&[0x84, 0x00, 0x01, 0x00, 0x00]), Some((65536, 5)));
    }

    /// Indefinite length is BER's, not DER's, and nothing here can act on it —
    /// so it is rejected rather than read as an empty value.
    #[test]
    fn indefinite_and_oversized_lengths_are_rejected() {
        assert_eq!(length(&[0x80]), None);
        assert_eq!(length(&[0x85, 1, 2, 3, 4, 5]), None);
        // A count that runs past the buffer.
        assert_eq!(length(&[0x82, 0x01]), None);
        assert_eq!(length(&[]), None);
    }

    #[test]
    fn a_tlv_reports_its_value_and_total_size() {
        let encoded = tlv(0x04, b"hello");
        let t = read(&encoded).expect("a TLV");
        assert_eq!(t.tag, 0x04);
        assert_eq!(t.value, b"hello");
        assert_eq!(t.total, 7);
        assert!(!t.is_constructed());
    }

    /// A value promising more than the buffer holds is not a TLV.
    #[test]
    fn a_truncated_value_is_not_read() {
        assert_eq!(read(&[0x04, 0x05, b'h', b'i']), None);
        assert_eq!(read(&[0x04]), None);
        assert_eq!(read(&[]), None);
    }

    /// Walking is what finds a field. These three fields encode identically,
    /// so a scan for the third one's bytes finds the first.
    #[test]
    fn children_are_walked_in_order() {
        let mut seq = Vec::new();
        seq.extend_from_slice(&tlv(0x02, &[0x05])); // version
        seq.extend_from_slice(&tlv(0x02, &[0x2A])); // something else
        seq.extend_from_slice(&tlv(0x0A, &[0x06])); // the error code
        let outer = tlv(0x30, &seq);
        let body = read(&outer).unwrap().value;

        let tags: Vec<u8> = children(body).map(|t| t.tag).collect();
        assert_eq!(tags, vec![0x02, 0x02, 0x0A]);
        // The enumerated is found by its tag, not by its position or bytes.
        assert_eq!(find(body, 0x0A).map(|t| t.value), Some(&[0x06][..]));
    }

    /// A malformed entry stops the walk. Continuing past a bad length means
    /// reading the wrong bytes, which is worse than stopping.
    #[test]
    fn a_bad_length_stops_the_walk_rather_than_desynchronising() {
        let mut seq = tlv(0x02, &[0x01]);
        seq.extend_from_slice(&[0x04, 0x7F, 0x00]); // claims 127 bytes, has 1
        seq.extend_from_slice(&tlv(0x02, &[0x02]));
        let found: Vec<u8> = children(&seq).map(|t| t.tag).collect();
        assert_eq!(found, vec![0x02], "the walk continued past a bad length");
    }

    #[test]
    fn context_tags_are_recognised() {
        // [0] constructed.
        let context = tlv(0xA0, &[0x01]);
        let t = read(&context).unwrap();
        assert_eq!(t.context_tag(), Some(0));
        assert!(t.is_constructed());
        // A universal SEQUENCE is not context-specific.
        let sequence = tlv(0x30, &[]);
        let s = read(&sequence).unwrap();
        assert_eq!(s.context_tag(), None);
        assert!(s.is_constructed());
    }

    /// A leading zero is DER's sign padding, not part of the value.
    #[test]
    fn integers_account_for_der_sign_padding() {
        assert_eq!(uint(&[0x06]), Some(6));
        assert_eq!(uint(&[0x00, 0xFF]), Some(255));
        assert_eq!(uint(&[0x01, 0x00]), Some(256));
        // Genuinely negative, which none of these fields ever are.
        assert_eq!(uint(&[0xFF]), None);
        assert_eq!(uint(&[]), None);
        // Wider than anything that could be a code.
        assert_eq!(uint(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
    }

    #[test]
    fn skip_lands_on_the_next_tlv() {
        let mut seq = tlv(0x02, &[0x01]);
        seq.extend_from_slice(&tlv(0x04, b"next"));
        let at = skip(&seq, 0).expect("a next position");
        assert_eq!(read(&seq[at..]).unwrap().value, b"next");
    }
}
