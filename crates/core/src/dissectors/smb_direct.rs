// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SMB Direct — SMB3 over RDMA transport (MS-SMBD).
//!
//! SMB Direct (SMBD) is a transport protocol that allows SMB2/3 messages to be
//! carried directly over RDMA (RoCE, InfiniBand, iWARP) SEND operations,
//! bypassing the TCP/IP stack.
//!
//! ## What to read in a capture
//!
//! An SMBD packet starts with a 20-byte transport header. The **CreditsRequested**
//! and **CreditsGranted** fields manage flow control between the client and
//! server. A Data Transfer message carries an SMB2/3 payload at **DataOffset**
//! (which must be 8-byte aligned).
//!
//! ## Guard
//!
//! SMB Direct packets carry no protocol identifier. To identify SMBD on RDMA SEND
//! payloads, the dissector uses structural rules from the MS-SMBD specification:
//!
//! 1. The payload must be at least 20 bytes.
//! 2. The **Reserved** field (bytes 6-7) must be exactly zero.
//! 3. The **DataOffset** (bytes 12-15) must be 8-byte aligned (e.g. 20, 24, etc.).
//! 4. If **DataLength** (bytes 16-19) is non-zero, it must fit within the payload,
//!    and the payload at `DataOffset` must start with the SMB2 magic `\xFESMB`.
//! 5. Alternatively, for connection negotiation (Negotiate Request/Response), the
//!    version fields (MinVersion/MaxVersion in bytes 0-4) must be exactly 1, and
//!    negotiated sizes must be non-zero.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Minimum SMBD header size (MS-SMBD §2.2).
const MIN_HEADER_LEN: usize = 20;

/// Whether the payload looks like an SMB Direct (SMBD) message.
#[allow(clippy::manual_is_multiple_of)]
pub(crate) fn looks_like_smb_direct(payload: &[u8]) -> bool {
    if payload.len() < MIN_HEADER_LEN {
        return false;
    }

    // Possibility A: Data Transfer Message (MS-SMBD §2.2.3)
    // Reserved field (bytes 6-7) must be 0.
    if payload[6..8] == [0, 0] {
        let data_offset =
            u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]) as usize;
        let data_length =
            u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as usize;

        if data_offset >= MIN_HEADER_LEN
            && data_offset % 8 == 0
            && data_offset + data_length <= payload.len()
        {
            if data_length >= 4 {
                if let Some(data) = payload.get(data_offset..data_offset + data_length) {
                    // If it contains a payload, verify it starts with SMB2 magic.
                    if data.starts_with(b"\xFESMB") {
                        return true;
                    }
                }
            } else {
                // Credit-only or keep-alive message (data_length is 0).
                // Verify that flags (bytes 4-5) is in a valid range (0 or 1).
                let flags = u16::from_le_bytes([payload[4], payload[5]]);
                if flags <= 1 {
                    return true;
                }
            }
        }
    }

    // Possibility B: Connection Negotiation (Request/Response) (MS-SMBD §2.2.1, §2.2.2)
    // Reserved field (bytes 4-5) must be 0.
    if payload[4..6] == [0, 0] {
        let min_version = u16::from_le_bytes([payload[0], payload[1]]);
        let max_version = u16::from_le_bytes([payload[2], payload[3]]);
        if min_version == 1 && max_version == 1 {
            let pref_send = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
            let pref_recv =
                u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
            if pref_send > 0 && pref_recv > 0 {
                return true;
            }
        }
    }

    false
}

/// Dissect an SMB Direct message.
pub fn dissect_smb_direct(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SmbDirect,
        summary: String::new(),
    };

    if payload.len() < MIN_HEADER_LEN {
        return DissectedResult {
            summary: "SMB Direct (truncated)".into(),
            ..base
        };
    }

    // Determine message type by version fields.
    let min_version = u16::from_le_bytes([payload[0], payload[1]]);
    let max_version = u16::from_le_bytes([payload[2], payload[3]]);

    if min_version == 1 && max_version == 1 {
        // Negotiation message
        let credits_requested = u16::from_le_bytes([payload[6], payload[7]]);
        let pref_send = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        // Negotiation Request has CreditsRequested in bytes 6-7.
        // Let's check preferred send size to describe it.
        return DissectedResult {
            summary: format!("SMB Direct Negotiate — credits requested {credits_requested}, send size {pref_send}"),
            ..base
        };
    }

    // Data Transfer message
    let credits_requested = u16::from_le_bytes([payload[0], payload[1]]);
    let credits_granted = u16::from_le_bytes([payload[2], payload[3]]);
    let data_offset =
        u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]) as usize;
    let data_length =
        u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as usize;

    if data_length > 0 && data_offset + data_length <= payload.len() {
        if let Some(data) = payload.get(data_offset..data_offset + data_length) {
            let inner = super::smb::dissect_smb(src_ip, dst_ip, src_port, dst_port, data);
            return DissectedResult {
                summary: format!(
                    "SMB Direct Data (req {credits_requested}, grant {credits_granted}) · {}",
                    inner.summary
                ),
                protocol: inner.protocol,
                ..base
            };
        }
    }

    DissectedResult {
        summary: format!(
            "SMB Direct Keep-Alive (req {credits_requested}, grant {credits_granted})"
        ),
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build an SMBD Data Transfer header.
    fn smbd_data(req: u16, grant: u16, offset: u32, len: u32, smb_payload: &[u8]) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&req.to_le_bytes());
        v.extend_from_slice(&grant.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // Flags
        v.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        v.extend_from_slice(&0u32.to_le_bytes()); // RemainingDataLength
        v.extend_from_slice(&offset.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        if offset as usize > MIN_HEADER_LEN {
            v.resize(offset as usize, 0);
        }
        v.extend_from_slice(smb_payload);
        v
    }

    /// Helper to build an SMB2 Negotiate Request payload (starting with \xFESMB).
    fn smb2_negotiate() -> Vec<u8> {
        let mut p = b"\xFESMB".to_vec();
        p.resize(64, 0);
        p
    }

    #[test]
    fn data_transfer_with_smb_payload_is_dissected() {
        let smb_data = smb2_negotiate();
        let payload = smbd_data(10, 5, 24, smb_data.len() as u32, &smb_data);
        assert!(looks_like_smb_direct(&payload));
        let r = dissect_smb_direct(None, None, 40000, 445, &payload);
        assert_eq!(r.protocol, Protocol::Smb);
        assert!(r.summary.contains("SMB Direct Data"), "{}", r.summary);
        assert!(r.summary.contains("req 10"), "{}", r.summary);
        assert!(r.summary.contains("grant 5"), "{}", r.summary);
        assert!(r.summary.contains("SMB2 NEGOTIATE"), "{}", r.summary);
    }

    #[test]
    fn keep_alive_is_dissected() {
        let payload = smbd_data(10, 5, 24, 0, &[]);
        assert!(looks_like_smb_direct(&payload));
        let r = dissect_smb_direct(None, None, 40000, 445, &payload);
        assert_eq!(r.protocol, Protocol::SmbDirect);
        assert!(r.summary.contains("SMB Direct Keep-Alive"), "{}", r.summary);
    }

    #[test]
    fn invalid_reserved_field_is_rejected() {
        let mut payload = smbd_data(10, 5, 24, 0, &[]);
        payload[6] = 1; // Corrupt Reserved field
        assert!(!looks_like_smb_direct(&payload));
    }
}
