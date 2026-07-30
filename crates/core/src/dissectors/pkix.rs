// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! `PKIStatusInfo` — how every PKIX protocol reports a refusal.
//!
//! CMP and the RFC 3161 timestamp protocol both answer with the same
//! structure: a status, an optional human-readable string, and a bit string of
//! reasons. Only the meanings of the bits differ, so the parsing lives here and
//! each protocol supplies its own table.
//!
//! ```text
//! PKIStatusInfo ::= SEQUENCE {
//!     status        PKIStatus,               -- INTEGER
//!     statusString  PKIFreeText   OPTIONAL,
//!     failInfo      PKIFailureInfo OPTIONAL  -- BIT STRING
//! }
//! ```
//!
//! Two details decide whether this reads correctly, and both have bitten:
//!
//! * The reasons are a **bit string**, so several can be set at once. Reporting
//!   only the first loses the rest, and the combination is often the diagnosis.
//! * A DER bit string's first content octet is a **count of unused trailing
//!   bits**, not data. Treating it as data shifts every bit by eight and
//!   reports the wrong reasons entirely.

use super::der;

/// A decoded status, with whichever reasons were set.
pub(crate) struct StatusInfo {
    pub status: u64,
    pub reasons: Vec<&'static str>,
}

/// The status values, which are shared across the PKIX protocols.
///
/// Zero means different words in different specs — CMP calls it `accepted` and
/// the timestamp protocol calls it `granted` — so the caller supplies that one.
pub(crate) fn status_name(status: u64) -> Option<&'static str> {
    Some(match status {
        1 => "granted with modifications",
        2 => "rejected",
        3 => "waiting",
        4 => "revocation warning",
        5 => "revocation notification",
        6 => "key update warning",
        _ => return None,
    })
}

/// Parse a `PKIStatusInfo`, naming set bits from `failures`.
pub(crate) fn parse(info: &[u8], failures: &[(u32, &'static str)]) -> Option<StatusInfo> {
    let sequence = der::read(info).filter(|t| t.tag == 0x30)?;
    let status = der::children(sequence.value)
        .find(|t| t.tag == 0x02)
        .and_then(|t| der::uint(t.value))?;

    let reasons = der::children(sequence.value)
        .find(|t| t.tag == 0x03)
        .and_then(|bits| set_bits(bits.value, failures))
        .unwrap_or_default();

    Some(StatusInfo { status, reasons })
}

/// Which named bits are set in a DER bit string.
fn set_bits(value: &[u8], names: &[(u32, &'static str)]) -> Option<Vec<&'static str>> {
    // The leading octet counts unused trailing bits; the data starts after it.
    let unused = *value.first()? as usize;
    let data = value.get(1..)?;
    if data.is_empty() || unused > 7 {
        return Some(Vec::new());
    }
    let total = data.len() * 8 - unused;
    Some(
        names
            .iter()
            .filter(|(bit, _)| {
                let bit = *bit as usize;
                bit < total
                    && data
                        .get(bit / 8)
                        .is_some_and(|b| b & (0x80 >> (bit % 8)) != 0)
            })
            .map(|(_, name)| *name)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &[(u32, &str)] = &[(0, "first"), (2, "third"), (14, "fifteenth")];

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// Build a PKIStatusInfo with the given status and set bits.
    fn info(status: u8, set: &[u32]) -> Vec<u8> {
        let mut parts = tlv(0x02, &[status]);
        if !set.is_empty() {
            let highest = set.iter().copied().max().unwrap_or(0) as usize;
            let bytes = highest / 8 + 1;
            let mut data = vec![0u8; bytes];
            for &bit in set {
                data[bit as usize / 8] |= 0x80 >> (bit % 8);
            }
            let mut value = vec![(bytes * 8 - (highest + 1)) as u8];
            value.extend_from_slice(&data);
            parts.extend_from_slice(&tlv(0x03, &value));
        }
        tlv(0x30, &parts)
    }

    #[test]
    fn the_status_and_reasons_are_read() {
        let parsed = parse(&info(2, &[2]), TABLE).expect("a status info");
        assert_eq!(parsed.status, 2);
        assert_eq!(parsed.reasons, vec!["third"]);
    }

    /// Several reasons can be set at once and all of them matter.
    #[test]
    fn every_set_bit_is_reported() {
        let parsed = parse(&info(2, &[0, 14]), TABLE).expect("a status info");
        assert_eq!(parsed.reasons, vec!["first", "fifteenth"]);
    }

    /// The first content octet counts unused bits and is not data. Read as
    /// data it shifts every bit by eight, which reports different reasons.
    #[test]
    fn the_unused_bit_count_is_not_data() {
        // Bit 0 set, in a one-byte string with seven unused bits.
        let one_bit = tlv(0x30, &[tlv(0x02, &[2]), tlv(0x03, &[7, 0x80])].concat());
        let parsed = parse(&one_bit, TABLE).expect("a status info");
        assert_eq!(parsed.reasons, vec!["first"]);
        // If the count byte were treated as data, bit 0 would come from 0x07 —
        // whose top bit is clear — and nothing would be reported.
        assert!(!parsed.reasons.is_empty());
    }

    /// A status with no failure bits is not a failure.
    #[test]
    fn a_status_without_reasons_reports_none() {
        let parsed = parse(&info(0, &[]), TABLE).expect("a status info");
        assert_eq!(parsed.status, 0);
        assert!(parsed.reasons.is_empty());
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(parse(&[], TABLE).is_none());
        assert!(parse(&[0x30], TABLE).is_none());
        // A sequence with no status integer.
        assert!(parse(&tlv(0x30, &tlv(0x04, &[1])), TABLE).is_none());
        // A bit string with only the count octet.
        let empty_bits = tlv(0x30, &[tlv(0x02, &[2]), tlv(0x03, &[0])].concat());
        assert!(parse(&empty_bits, TABLE).unwrap().reasons.is_empty());
    }
}
