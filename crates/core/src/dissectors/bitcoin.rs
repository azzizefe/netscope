// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every message opens with a four-byte magic that also says which network it
/// belongs to — which is worth surfacing, because a node accidentally pointed
/// at testnet looks identical to a healthy one until you read this field.
fn network_name(magic: [u8; 4]) -> Option<&'static str> {
    Some(match magic {
        [0xF9, 0xBE, 0xB4, 0xD9] => "mainnet",
        [0x0B, 0x11, 0x09, 0x07] => "testnet3",
        [0x0A, 0x03, 0xCF, 0x40] => "signet",
        [0xFA, 0xBF, 0xB5, 0xDA] => "regtest",
        _ => return None,
    })
}

/// Magic, a twelve-byte command name, the payload length and a checksum.
const OFFSET_COMMAND: usize = 4;
const COMMAND_LEN: usize = 12;
const OFFSET_LENGTH: usize = 16;

/// Whether a payload is a Bitcoin protocol message.
///
/// The network magic is a genuine four-byte constant, which makes this one of
/// the few protocols here that can be recognised on content alone without risk.
pub(crate) fn looks_like_bitcoin(payload: &[u8]) -> bool {
    parse(payload).is_some()
}

fn parse(payload: &[u8]) -> Option<(&'static str, String, u32)> {
    let magic: [u8; 4] = payload.get(..4)?.try_into().ok()?;
    let network = network_name(magic)?;

    // The command is an ASCII name padded with NULs.
    let field = payload.get(OFFSET_COMMAND..OFFSET_COMMAND + COMMAND_LEN)?;
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let command = std::str::from_utf8(&field[..end]).ok()?;
    if command.is_empty() || !command.bytes().all(|b| b.is_ascii_lowercase()) {
        return None;
    }

    let length = u32::from_le_bytes([
        *payload.get(OFFSET_LENGTH)?,
        *payload.get(OFFSET_LENGTH + 1)?,
        *payload.get(OFFSET_LENGTH + 2)?,
        *payload.get(OFFSET_LENGTH + 3)?,
    ]);
    Some((network, command.to_string(), length))
}

/// A note on what the common messages mean, so a reader does not have to know
/// the protocol to follow what a node is doing.
fn command_note(command: &str) -> Option<&'static str> {
    Some(match command {
        "version" => "introducing itself",
        "verack" => "introduction accepted",
        "inv" => "announcing what it has",
        "getdata" => "asking for something announced",
        "tx" => "a transaction",
        "block" => "a block",
        "headers" => "block headers",
        "getheaders" => "asking for block headers",
        "getblocks" => "asking for blocks",
        "addr" | "addrv2" => "sharing peer addresses",
        "getaddr" => "asking for peers",
        "ping" | "pong" => "keepalive",
        "reject" => "refusing a message",
        "notfound" => "does not have what was asked for",
        "feefilter" => "setting a minimum fee",
        "sendcmpct" | "cmpctblock" | "blocktxn" | "getblocktxn" => "compact block relay",
        _ => return None,
    })
}

/// Dissect a Bitcoin protocol message (TCP 8333 on mainnet, and the testnet
/// ports).
pub fn dissect_bitcoin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some((network, command, length)) => {
            let network_note = if network == "mainnet" {
                String::new()
            } else {
                format!(" [{network}]")
            };
            match command_note(&command) {
                Some(note) => format!("Bitcoin {command}{network_note} — {note}, {length} bytes"),
                None => format!("Bitcoin {command}{network_note} — {length} bytes"),
            }
        }
        None => format!("Bitcoin ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bitcoin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
    const TESTNET: [u8; 4] = [0x0B, 0x11, 0x09, 0x07];

    fn message(magic: [u8; 4], command: &str, length: u32) -> Vec<u8> {
        let mut p = magic.to_vec();
        let mut field = [0u8; COMMAND_LEN];
        field[..command.len()].copy_from_slice(command.as_bytes());
        p.extend_from_slice(&field);
        p.extend_from_slice(&length.to_le_bytes());
        p.extend_from_slice(&[0u8; 4]); // checksum
        p
    }

    #[test]
    fn transactions_and_blocks_are_named() {
        let r = dissect_bitcoin(None, None, 40000, 8333, &message(MAINNET, "tx", 250));
        assert_eq!(r.protocol, Protocol::Bitcoin);
        assert_eq!(r.summary, "Bitcoin tx — a transaction, 250 bytes");
        assert_eq!(
            dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "block", 1_000_000)).summary,
            "Bitcoin block — a block, 1000000 bytes"
        );
    }

    /// A node pointed at the wrong network looks perfectly healthy until you
    /// read the magic, so the network is called out whenever it is not mainnet.
    #[test]
    fn a_non_mainnet_network_is_flagged() {
        let r = dissect_bitcoin(None, None, 1, 18333, &message(TESTNET, "version", 100));
        assert_eq!(
            r.summary,
            "Bitcoin version [testnet3] — introducing itself, 100 bytes"
        );
        // Mainnet is the default and is not worth repeating on every line.
        let r = dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "version", 100));
        assert_eq!(r.summary, "Bitcoin version — introducing itself, 100 bytes");
    }

    #[test]
    fn the_announce_and_fetch_cycle_is_legible() {
        assert!(
            dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "inv", 37))
                .summary
                .contains("announcing what it has")
        );
        assert!(
            dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "getdata", 37))
                .summary
                .contains("asking for something announced")
        );
        assert!(
            dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "notfound", 37))
                .summary
                .contains("does not have what was asked for")
        );
    }

    /// A command with no note still reports its name, which is how the protocol
    /// refers to it anyway.
    #[test]
    fn an_unfamiliar_command_still_names_itself() {
        let r = dissect_bitcoin(None, None, 1, 8333, &message(MAINNET, "wtxidrelay", 0));
        assert_eq!(r.summary, "Bitcoin wtxidrelay — 0 bytes");
    }

    /// The magic is a real four-byte constant, so recognition is safe on
    /// content — unlike the protocols here that had to fall back to ports.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_bitcoin(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_bitcoin(&[0u8; 24]));
        assert!(!looks_like_bitcoin(&[]));
        assert!(looks_like_bitcoin(&message(MAINNET, "ping", 8)));
    }

    /// A command field carrying anything but a lowercase ASCII name means the
    /// magic matched by coincidence.
    #[test]
    fn a_non_ascii_command_is_rejected() {
        let mut p = MAINNET.to_vec();
        p.extend_from_slice(&[0xFF; COMMAND_LEN]);
        p.extend_from_slice(&[0u8; 8]);
        assert!(!looks_like_bitcoin(&p));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_bitcoin(None, None, 1, 8333, &MAINNET);
        assert_eq!(r.summary, "Bitcoin (4 bytes)");
    }
}
