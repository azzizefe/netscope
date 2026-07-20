// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NBD message (TCP 10809) — Network Block Device, which exports a
/// raw block device over the network so a client can mount it as a local disk.
/// The handshake opens with "NBDMAGIC"; requests and replies have their own
/// magic numbers.
pub fn dissect_nbd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"NBDMAGIC") {
        "NBD handshake (server greeting)".to_string()
    } else if payload.starts_with(b"IHAVEOPT") {
        "NBD option negotiation".to_string()
    } else if payload.len() >= 8 {
        let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        match magic {
            0x2560_9513 => {
                let cmd = u16::from_be_bytes([payload[6], payload[7]]);
                // A generic "request" here would render as "NBD request
                // request", so unknown commands report their number instead.
                match cmd {
                    0 => "NBD read request".to_string(),
                    1 => "NBD write request".to_string(),
                    2 => "NBD disconnect request".to_string(),
                    3 => "NBD flush request".to_string(),
                    4 => "NBD trim request".to_string(),
                    other => format!("NBD request — command {other}"),
                }
            }
            0x6744_6698 => "NBD reply".to_string(),
            _ => format!("NBD data ({})", super::bytes(payload.len() as u64)),
        }
    } else {
        format!("NBD ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nbd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_request() {
        let mut p = 0x2560_9513u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x00, 0x00]); // flags
        p.extend_from_slice(&1u16.to_be_bytes()); // command: write
        let r = dissect_nbd(None, None, 40000, 10809, &p);
        assert_eq!(r.protocol, Protocol::Nbd);
        assert_eq!(r.summary, "NBD write request");
    }

    #[test]
    fn greeting() {
        let r = dissect_nbd(None, None, 10809, 40000, b"NBDMAGICIHAVEOPT");
        assert!(r.summary.contains("handshake"), "{}", r.summary);
    }
}
