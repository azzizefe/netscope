// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The Redis cluster bus — how nodes gossip about each other.
//!
//! Separate from the client protocol and on a separate port (the data port plus
//! ten thousand), this is where a cluster decides which nodes are alive. It is
//! worth reading because the interesting failures happen here rather than on
//! the client side: a node marked as failing, or a vote being requested, is the
//! cause of the client-visible errors rather than a symptom of them.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every message opens with this signature.
const SIGNATURE: &[u8] = b"RCmb";
/// Signature, total length, protocol version, then the type.
const OFFSET_VERSION: usize = 8;
const OFFSET_TYPE: usize = 10;
/// The sender's name, forty hex characters, follows the type and count fields.
const OFFSET_SENDER: usize = 12;
const NAME_LEN: usize = 40;

/// Message types (`clusterMsg` in the Redis source).
fn message_name(kind: u16) -> Option<&'static str> {
    Some(match kind {
        0 => "PING",
        1 => "PONG",
        2 => "MEET (a node joining)",
        3 => "FAIL (a node declared down)",
        4 => "PUBLISH",
        5 => "failover auth request",
        6 => "failover auth granted",
        7 => "config update",
        8 => "MFSTART (manual failover)",
        9 => "module",
        10 => "PUBLISHSHARD",
        _ => return None,
    })
}

/// Whether a payload is a cluster bus message.
///
/// The signature is a genuine four-byte constant, so this is safe to check on
/// content — the bus runs on a port derived from the data port rather than a
/// fixed one, so recognition matters.
pub(crate) fn looks_like_cluster_bus(payload: &[u8]) -> bool {
    payload.len() > OFFSET_SENDER && payload.starts_with(SIGNATURE)
}

/// The sending node's name, which is how a cluster identifies its members.
fn sender(payload: &[u8]) -> Option<String> {
    let name = payload.get(OFFSET_SENDER..OFFSET_SENDER + NAME_LEN)?;
    let text = std::str::from_utf8(name).ok()?;
    if !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // The full name is forty characters; the first twelve identify it well
    // enough to follow a conversation without filling the column.
    Some(text[..12].to_string())
}

/// Dissect a Redis cluster bus message.
pub fn dissect_redis_cluster(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if !looks_like_cluster_bus(payload) {
        format!("Redis cluster bus ({})", super::bytes(payload.len() as u64))
    } else {
        let kind = u16::from_be_bytes([payload[OFFSET_TYPE], payload[OFFSET_TYPE + 1]]);
        let version = u16::from_be_bytes([payload[OFFSET_VERSION], payload[OFFSET_VERSION + 1]]);
        let name = match message_name(kind) {
            Some(n) => n.to_string(),
            None => format!("type {kind}"),
        };
        match sender(payload) {
            Some(node) => format!("Redis cluster {name} — from {node} (bus v{version})"),
            None => format!("Redis cluster {name} (bus v{version})"),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RedisCluster,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a cluster bus message from the given node.
    fn message(kind: u16, node: &str) -> Vec<u8> {
        let mut p = SIGNATURE.to_vec();
        p.extend_from_slice(&2000u32.to_be_bytes()); // total length
        p.extend_from_slice(&1u16.to_be_bytes()); // protocol version
        p.extend_from_slice(&kind.to_be_bytes());
        p.extend_from_slice(node.as_bytes());
        p.extend_from_slice(&[0u8; 32]);
        p
    }

    const NODE: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";

    /// The everyday traffic is nodes checking on each other.
    #[test]
    fn gossip_is_named() {
        let r = dissect_redis_cluster(None, None, 16379, 16379, &message(0, NODE));
        assert_eq!(r.protocol, Protocol::RedisCluster);
        assert_eq!(r.summary, "Redis cluster PING — from a1b2c3d4e5f6 (bus v1)");
    }

    /// The messages that matter: a node being declared down, and the vote that
    /// follows. These are the cause of client-visible errors, not a symptom.
    #[test]
    fn failure_and_failover_are_named() {
        assert!(
            dissect_redis_cluster(None, None, 1, 16379, &message(3, NODE))
                .summary
                .contains("FAIL (a node declared down)")
        );
        assert!(
            dissect_redis_cluster(None, None, 1, 16379, &message(5, NODE))
                .summary
                .contains("failover auth request")
        );
        assert!(
            dissect_redis_cluster(None, None, 1, 16379, &message(6, NODE))
                .summary
                .contains("failover auth granted")
        );
    }

    /// A MEET is a node being added, which explains a burst of gossip.
    #[test]
    fn a_joining_node_is_named() {
        assert!(
            dissect_redis_cluster(None, None, 1, 16379, &message(2, NODE))
                .summary
                .contains("MEET (a node joining)")
        );
    }

    /// The sender's name is how a conversation is followed across a cluster of
    /// many nodes.
    #[test]
    fn the_sender_is_identified() {
        let other = "ffffffffffffffffffffffffffffffffffffffff";
        let a = dissect_redis_cluster(None, None, 1, 16379, &message(0, NODE));
        let b = dissect_redis_cluster(None, None, 1, 16379, &message(0, other));
        assert!(a.summary.contains("a1b2c3d4e5f6"));
        assert!(b.summary.contains("ffffffffffff"));
    }

    /// The signature is a real constant, which matters because the bus port is
    /// derived from the data port rather than fixed.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_cluster_bus(b"*1\r\n$4\r\nPING\r\n"));
        assert!(!looks_like_cluster_bus(b"GET / HTTP/1.1"));
        assert!(!looks_like_cluster_bus(&[]));
        assert!(looks_like_cluster_bus(&message(0, NODE)));
    }

    /// A name that is not hex means the offsets are wrong, so the field is
    /// dropped rather than rendered as noise.
    #[test]
    fn a_nonsense_sender_is_not_shown() {
        let mut p = message(0, NODE);
        p[OFFSET_SENDER..OFFSET_SENDER + 4].copy_from_slice(b"!!!!");
        let r = dissect_redis_cluster(None, None, 1, 16379, &p);
        assert_eq!(r.summary, "Redis cluster PING (bus v1)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_redis_cluster(None, None, 1, 16379, b"RCmb");
        assert_eq!(r.summary, "Redis cluster bus (4 bytes)");
    }
}
