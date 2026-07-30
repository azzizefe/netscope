// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AppleTalk DDP packet (EtherType 0x809B) — the network layer of
/// classic Mac networking. The long DDP header ends with a protocol type byte
/// naming the upper-layer service.
pub fn dissect_atalk(payload: &[u8]) -> DissectedResult {
    // Long DDP header: len(2) checksum(2) dst net(2) src net(2) dst node(1)
    // src node(1) dst socket(1) src socket(1) type(1).
    let summary = match payload.get(12) {
        Some(&t) => {
            let name = match t {
                1 => "RTMP (routing)",
                2 => "NBP (name binding)",
                3 => "ATP (transaction)",
                4 => "AEP (echo)",
                5 => "RTMP request",
                6 => "ZIP (zone information)",
                7 => "ADSP (data stream)",
                _ => "datagram",
            };
            format!("AppleTalk DDP — {name}")
        }
        None => "AppleTalk DDP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Atalk,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_binding() {
        let mut p = vec![0u8; 12];
        p.push(2); // DDP type: NBP
        let r = dissect_atalk(&p);
        assert_eq!(r.protocol, Protocol::Atalk);
        assert!(r.summary.contains("NBP"), "{}", r.summary);
    }
}
