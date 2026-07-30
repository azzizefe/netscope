// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Consul RPC — the server port where leadership is decided (TCP 8300).
//!
//! Consul multiplexes several unrelated protocols onto one port, and the first
//! byte of the connection says which one. That byte is the whole reason this is
//! worth dissecting: it separates ordinary agent RPC from Raft, and Raft is
//! where a cluster's health actually shows.
//!
//! A steady cluster carries `AppendEntries` — the leader replicating log
//! entries and using the same call as its heartbeat. `RequestVote` means a
//! follower stopped hearing that heartbeat and called an election. A capture
//! full of RequestVote is a cluster that cannot hold a leader, which presents
//! to users as writes failing intermittently with no single server looking
//! broken. `InstallSnapshot` means a follower fell so far behind that replaying
//! the log was abandoned in favour of shipping the entire state.
//!
//! The type bytes are 0-9, which RFC 7983 leaves unassigned as TLS content
//! types precisely so a port can be multiplexed this way. That is what makes
//! recognition safe: a TLS record on this port cannot collide with them, and
//! Consul itself uses that fact to tell native TLS from its own framing.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The highest type byte Consul assigns. Everything above is TLS.
const MAX_TYPE: u8 = 9;

/// Which protocol is riding the RPC port.
fn rpc_type(byte: u8) -> Option<&'static str> {
    Some(match byte {
        0 => "agent RPC",
        1 => "Raft",
        2 => "multiplex",
        3 => "TLS",
        4 => "multiplex v2",
        5 => "snapshot",
        6 => "gossip",
        7 => "TLS (insecure)",
        8 => "gRPC",
        MAX_TYPE => "Raft forwarding",
        _ => return None,
    })
}

/// What a Raft peer is asking of another, from the byte after the type.
fn raft_call(byte: u8) -> Option<&'static str> {
    Some(match byte {
        0 => "AppendEntries (replication and heartbeat)",
        1 => "RequestVote — an election is under way",
        2 => "InstallSnapshot — a follower fell too far behind to catch up",
        3 => "TimeoutNow — leadership is being handed over",
        _ => return None,
    })
}

/// Whether a payload opens a Consul RPC connection.
///
/// This is the first byte of the stream, so it only matches at the start of a
/// connection; mid-stream segments fall through to the port binding.
pub(crate) fn looks_like_consul_rpc(payload: &[u8]) -> bool {
    payload.first().is_some_and(|&b| rpc_type(b).is_some())
}

/// Dissect a Consul RPC message.
pub fn dissect_consul_rpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ConsulRpc,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&byte) = payload.first() else {
        return "Consul RPC".to_string();
    };
    let Some(kind) = rpc_type(byte) else {
        // Above the assigned range this is native TLS, which the TLS dissector
        // would have claimed had the port not been bound here first.
        return if byte > MAX_TYPE {
            "Consul RPC — TLS".to_string()
        } else {
            format!("Consul RPC (type {byte})")
        };
    };

    // Raft frames its own call type immediately after Consul's, and that inner
    // byte is what distinguishes a healthy cluster from one holding an election.
    if matches!(byte, 1 | MAX_TYPE) {
        if let Some(call) = payload.get(1).and_then(|&b| raft_call(b)) {
            return format!("Consul {kind} — {call}");
        }
    }
    format!("Consul RPC — {kind}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this dissector exists: an election is visible on the wire,
    /// and is what a cluster that cannot hold a leader looks like.
    #[test]
    fn an_election_is_spelled_out() {
        let r = dissect_consul_rpc(None, None, 50000, 8300, &[1, 1]);
        assert_eq!(r.protocol, Protocol::ConsulRpc);
        assert!(
            r.summary.contains("an election is under way"),
            "{}",
            r.summary
        );
    }

    /// A healthy cluster looks different from one that is re-electing, and a
    /// lagging follower different again.
    #[test]
    fn the_raft_calls_are_distinguished() {
        assert!(describe(&[1, 0]).contains("AppendEntries"));
        assert!(describe(&[1, 2]).contains("fell too far behind"));
        assert!(describe(&[1, 3]).contains("leadership is being handed over"));
    }

    /// Raft forwarding carries the same inner call type.
    #[test]
    fn forwarded_raft_is_read_the_same_way() {
        let summary = describe(&[MAX_TYPE, 1]);
        assert!(summary.contains("Raft forwarding"), "{summary}");
        assert!(summary.contains("an election is under way"), "{summary}");
    }

    #[test]
    fn the_other_types_are_named() {
        assert_eq!(describe(&[0]), "Consul RPC — agent RPC");
        assert_eq!(describe(&[5]), "Consul RPC — snapshot");
        assert_eq!(describe(&[6]), "Consul RPC — gossip");
        assert_eq!(describe(&[8]), "Consul RPC — gRPC");
    }

    /// Consul relies on its type bytes being unusable as a TLS content type,
    /// so anything above the assigned range is a real TLS record.
    #[test]
    fn tls_is_recognised_rather_than_guessed_at() {
        // 22 is the TLS handshake content type.
        assert_eq!(describe(&[22, 3, 1]), "Consul RPC — TLS");
        assert!(!looks_like_consul_rpc(&[22, 3, 1]));
    }

    /// Only the opening byte of a connection identifies this, so recognition
    /// stays narrow.
    #[test]
    fn recognition_is_limited_to_the_assigned_bytes() {
        for byte in 0..=MAX_TYPE {
            assert!(looks_like_consul_rpc(&[byte]), "{byte}");
        }
        assert!(!looks_like_consul_rpc(&[MAX_TYPE + 1]));
        assert!(!looks_like_consul_rpc(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_consul_rpc(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "Consul RPC");
        // A Raft connection whose call byte has not arrived yet.
        assert_eq!(describe(&[1]), "Consul RPC — Raft");
        // A Raft call type that is not defined.
        assert_eq!(describe(&[1, 200]), "Consul RPC — Raft");
    }
}
