// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! memberlist — the gossip that decides a node is dead (UDP 7946).
//!
//! HashiCorp's memberlist library is the membership layer under Serf, Consul
//! and Nomad. Nodes gossip about each other over UDP: a failed direct ping
//! becomes an *indirect* ping through a third node, and if that also fails the
//! node is broadcast as `suspect`, then `dead`.
//!
//! That escalation is the reason to read this. When a cluster evicts a node,
//! the question is always "who decided, and on what evidence" — and both
//! answers are on the wire. The `suspect` and `dead` messages name the node
//! being accused *and* the node doing the accusing, so a capture shows whether
//! one flapping member is being blamed by the whole cluster or whether a single
//! peer with a broken path is evicting everyone it cannot reach.
//!
//! It also separates the two events that look identical in a cluster's logs: a
//! node that shut down cleanly sends a `dead` message about itself, so `Node`
//! and `From` are equal. A node that was evicted has someone else's name in
//! `From`. The library draws exactly that line — a self-sent `dead` marks the
//! member "left" rather than "dead".
//!
//! Message bodies are MessagePack maps keyed by field name.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Wrapper that carries a cluster label ahead of the real message. Its value is
/// deliberately far above the message types so the two cannot be confused.
const HAS_LABEL: u8 = 244;
/// Wrapper that prefixes a CRC32 over the message that follows.
const HAS_CRC: u8 = 12;
/// Wrapper holding several gossiped messages in one packet.
const COMPOUND: u8 = 7;

/// What a memberlist message is for. The numbers are part of the protocol and
/// are only ever appended to.
fn message_name(message: u8) -> Option<&'static str> {
    Some(match message {
        0 => "ping",
        1 => "indirect ping",
        2 => "ack",
        3 => "suspect",
        4 => "alive",
        5 => "dead",
        6 => "state sync",
        COMPOUND => "compound",
        8 => "user message",
        9 => "compressed",
        10 => "encrypted",
        11 => "nack",
        HAS_CRC => "checksummed",
        13 => "error",
        HAS_LABEL => "labelled",
        _ => return None,
    })
}

/// Step over one MessagePack value, returning its total encoded length.
///
/// Only the encodings memberlist actually emits are handled; anything else
/// makes the walk give up rather than guess a length and desynchronise.
fn skip_value(b: &[u8], depth: u8) -> Option<usize> {
    // A hostile packet can nest maps arbitrarily deep, and this recurses.
    if depth > 8 {
        return None;
    }
    let &tag = b.first()?;
    let elements = |n: usize, mut off: usize| -> Option<usize> {
        for _ in 0..n {
            off += skip_value(b.get(off..)?, depth + 1)?;
        }
        Some(off)
    };
    let len_at = |off: usize, width: usize| -> Option<usize> {
        let bytes = b.get(off..off + width)?;
        Some(bytes.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize))
    };
    Some(match tag {
        // Positive and negative fixint, nil, false, true.
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => 1,
        0xcc | 0xd0 => 2,
        0xcd | 0xd1 => 3,
        0xca | 0xce | 0xd2 => 5,
        0xcb | 0xcf | 0xd3 => 9,
        0xa0..=0xbf => 1 + (tag & 0x1f) as usize,
        0xc4 | 0xd9 => 2 + len_at(1, 1)?,
        0xc5 | 0xda => 3 + len_at(1, 2)?,
        0xc6 | 0xdb => 5 + len_at(1, 4)?,
        0x90..=0x9f => elements((tag & 0x0f) as usize, 1)?,
        0xdc => elements(len_at(1, 2)?, 3)?,
        0xdd => elements(len_at(1, 4)?, 5)?,
        // A map is a flat run of alternating keys and values.
        0x80..=0x8f => elements((tag & 0x0f) as usize * 2, 1)?,
        0xde => elements(len_at(1, 2)?.checked_mul(2)?, 3)?,
        0xdf => elements(len_at(1, 4)?.checked_mul(2)?, 5)?,
        _ => return None,
    })
}

/// Read a MessagePack string, returning it with its total encoded length.
fn read_str(b: &[u8]) -> Option<(&str, usize)> {
    let &tag = b.first()?;
    let (start, len) = match tag {
        0xa0..=0xbf => (1, (tag & 0x1f) as usize),
        // `str8` and `bin8` share a layout; a name can arrive as either.
        0xd9 | 0xc4 => (2, *b.get(1)? as usize),
        0xda | 0xc5 => (3, u16::from_be_bytes([*b.get(1)?, *b.get(2)?]) as usize),
        _ => return None,
    };
    let text = std::str::from_utf8(b.get(start..start + len)?).ok()?;
    Some((text, start + len))
}

/// Read the entry count and body offset of a MessagePack map.
fn map_header(b: &[u8]) -> Option<(usize, usize)> {
    let &tag = b.first()?;
    Some(match tag {
        0x80..=0x8f => ((tag & 0x0f) as usize, 1),
        0xde => (u16::from_be_bytes([*b.get(1)?, *b.get(2)?]) as usize, 3),
        _ => return None,
    })
}

/// Look up a string field by name, walking the map entry by entry.
///
/// Deliberately not a scan for the key's bytes: `Node` and `From` hold node
/// names, and a node is free to call itself "From", so a search finds the
/// wrong one. Walking is the only way to know a match is a key and not a value.
fn map_str(b: &[u8], key: &str) -> Option<String> {
    let (count, mut off) = map_header(b)?;
    for _ in 0..count {
        let (name, used) = read_str(b.get(off..)?)?;
        off += used;
        let value = b.get(off..)?;
        if name == key {
            return read_str(value).map(|(s, _)| super::truncate(s, 64));
        }
        off += skip_value(value, 0)?;
    }
    None
}

/// Strip the label and checksum wrappers, returning the message inside.
///
/// Both are optional and the label always comes first, so a packet may carry
/// neither, either, or both.
fn unwrap(payload: &[u8]) -> &[u8] {
    let mut body = payload;
    if body.first() == Some(&HAS_LABEL) {
        let len = body.get(1).copied().unwrap_or(0) as usize;
        body = body.get(2 + len..).unwrap_or(&[]);
    }
    if body.first() == Some(&HAS_CRC) && body.len() >= 5 {
        body = &body[5..];
    }
    body
}

/// Whether a payload is memberlist gossip: a known message type, and — for the
/// types carrying one — a MessagePack map where the body should start.
pub(crate) fn looks_like_memberlist(payload: &[u8]) -> bool {
    let body = unwrap(payload);
    let Some(&message) = body.first() else {
        return false;
    };
    if message_name(message).is_none() {
        return false;
    }
    // The gossip that matters carries a map. The wrapper-only and opaque types
    // have nothing to check, so the type byte is all the evidence there is.
    if matches!(message, 0..=6 | 11 | 13) {
        return map_header(&body[1..]).is_some();
    }
    true
}

/// Dissect a memberlist gossip packet.
pub fn dissect_memberlist(
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
        protocol: Protocol::Memberlist,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let body = unwrap(payload);
    let Some(&message) = body.first() else {
        return "memberlist".to_string();
    };
    let fields = &body[1..];

    // A compound packet is the ordinary case on a busy cluster: gossip is
    // batched. Report the first message in it, since that is the news.
    if message == COMPOUND {
        let count = fields.first().copied().unwrap_or(0) as usize;
        let first = fields
            .get(1 + count * 2..)
            .filter(|rest| !rest.is_empty())
            .map(describe)
            .filter(|s| s != "memberlist");
        return match (count, first) {
            (_, Some(inner)) if count > 1 => format!("{inner} (+{} more gossiped)", count - 1),
            (_, Some(inner)) => inner,
            _ => format!("memberlist — {count} gossiped messages"),
        };
    }

    let Some(name) = message_name(message) else {
        return format!("memberlist (type {message})");
    };
    let node = map_str(fields, "Node");
    let from = map_str(fields, "From");

    match (message, node, from) {
        // The accusation, and who is making it.
        (3, Some(node), Some(from)) => format!("memberlist — {from} suspects {node} has failed"),
        // A node's own name in From means it announced its own departure.
        (5, Some(node), Some(from)) if node == from => {
            format!("memberlist — {node} left the cluster")
        }
        (5, Some(node), Some(from)) => format!("memberlist — {from} declared {node} dead"),
        (4, Some(node), _) => format!("memberlist — {node} is alive"),
        (_, Some(node), _) => format!("memberlist {name} — {node}"),
        _ => format!("memberlist {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a MessagePack fixstr.
    fn s(text: &str) -> Vec<u8> {
        let mut v = vec![0xa0 | text.len() as u8];
        v.extend_from_slice(text.as_bytes());
        v
    }

    /// Build a message body: a fixmap of the given string key/value pairs,
    /// preceded by an `Incarnation` number, which is what really rides there.
    fn body(message: u8, pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut v = vec![message, 0x80 | (pairs.len() + 1) as u8];
        v.extend_from_slice(&s("Incarnation"));
        v.push(0x07);
        for (k, val) in pairs {
            v.extend_from_slice(&s(k));
            v.extend_from_slice(&s(val));
        }
        v
    }

    /// The reason this dissector exists: an eviction names both the node being
    /// removed and the node that decided it.
    #[test]
    fn an_eviction_names_the_accuser() {
        let p = body(5, &[("Node", "web-3"), ("From", "web-1")]);
        let r = dissect_memberlist(None, None, 7946, 7946, &p);
        assert_eq!(r.protocol, Protocol::Memberlist);
        assert_eq!(r.summary, "memberlist — web-1 declared web-3 dead");
    }

    /// A clean shutdown and an eviction are the same message type, separated
    /// only by whether the node is talking about itself.
    #[test]
    fn a_graceful_leave_is_not_an_eviction() {
        let left = describe(&body(5, &[("Node", "web-3"), ("From", "web-3")]));
        assert_eq!(left, "memberlist — web-3 left the cluster");
        let evicted = describe(&body(5, &[("Node", "web-3"), ("From", "web-9")]));
        assert!(evicted.contains("declared web-3 dead"), "{evicted}");
    }

    /// Suspicion is the step before eviction, and is where a one-sided network
    /// partition first becomes visible.
    #[test]
    fn suspicion_is_reported_with_both_names() {
        assert_eq!(
            describe(&body(3, &[("Node", "db-2"), ("From", "db-1")])),
            "memberlist — db-1 suspects db-2 has failed"
        );
    }

    #[test]
    fn the_other_message_types_are_named() {
        assert_eq!(
            describe(&body(4, &[("Node", "web-1")])),
            "memberlist — web-1 is alive"
        );
        assert_eq!(
            describe(&body(0, &[("Node", "web-1")])),
            "memberlist ping — web-1"
        );
        assert_eq!(
            describe(&body(1, &[("Node", "web-1")])),
            "memberlist indirect ping — web-1"
        );
    }

    /// A field is found by walking the map, not by searching it. A node that
    /// names itself "From" puts that string in a *value*, and a scan would
    /// return the following field instead.
    #[test]
    fn a_node_named_like_a_key_does_not_confuse_the_walk() {
        let p = body(5, &[("Node", "From"), ("From", "web-1")]);
        assert_eq!(describe(&p), "memberlist — web-1 declared From dead");
    }

    /// Gossip is batched, and the first message in the batch is the news.
    #[test]
    fn a_compound_packet_reports_what_is_inside_it() {
        let inner = body(5, &[("Node", "web-3"), ("From", "web-1")]);
        let other = body(4, &[("Node", "web-2")]);
        let mut p = vec![COMPOUND, 2];
        p.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        p.extend_from_slice(&(other.len() as u16).to_be_bytes());
        p.extend_from_slice(&inner);
        p.extend_from_slice(&other);
        assert_eq!(
            describe(&p),
            "memberlist — web-1 declared web-3 dead (+1 more gossiped)"
        );
    }

    /// The label and checksum wrappers sit in front of the real message, in
    /// that order, and either may be absent.
    #[test]
    fn the_wrappers_are_stripped() {
        let inner = body(4, &[("Node", "web-1")]);
        let expected = "memberlist — web-1 is alive";

        let mut labelled = vec![HAS_LABEL, 3];
        labelled.extend_from_slice(b"dc1");
        labelled.extend_from_slice(&inner);
        assert_eq!(describe(&labelled), expected);

        let mut crc = vec![HAS_CRC, 0xde, 0xad, 0xbe, 0xef];
        crc.extend_from_slice(&inner);
        assert_eq!(describe(&crc), expected);

        // Both at once, label outermost.
        let mut both = vec![HAS_LABEL, 3];
        both.extend_from_slice(b"dc1");
        both.extend_from_slice(&crc);
        assert_eq!(describe(&both), expected);
    }

    /// The port is a convention rather than an assignment, so the framing has
    /// to agree before a flow is claimed.
    #[test]
    fn recognition_needs_the_framing_to_agree() {
        assert!(looks_like_memberlist(&body(4, &[("Node", "web-1")])));
        assert!(looks_like_memberlist(&body(0, &[("Node", "web-1")])));
        assert!(!looks_like_memberlist(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_memberlist(&[]));
        // A known type byte, but no map where the body belongs.
        assert!(!looks_like_memberlist(&[5, 0xff, 0xff, 0xff]));
        // A type the protocol does not define.
        assert!(!looks_like_memberlist(&[200, 0x81]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "memberlist");
        assert_eq!(describe(&[4]), "memberlist alive");
        assert_eq!(describe(&[4, 0x82]), "memberlist alive");
        assert_eq!(describe(&[HAS_LABEL]), "memberlist");
        assert_eq!(describe(&[COMPOUND]), "memberlist — 0 gossiped messages");
        // A map promising more entries than the packet holds.
        assert_eq!(describe(&[5, 0x8f, 0xa4, b'N']), "memberlist dead");
    }

    /// Deeply nested values must not run the walk out of stack.
    #[test]
    fn nesting_is_bounded() {
        let deep = vec![0x81; 64];
        assert!(skip_value(&deep, 0).is_none());
    }
}
