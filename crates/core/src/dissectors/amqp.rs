// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! AMQP 0-9-1, the protocol RabbitMQ speaks.
//!
//! Only the opening handshake was recognised before, so every frame after it
//! read as undifferentiated "message queuing traffic". The method within each
//! frame is what a reader wants: a Basic.Publish is a message going in, a
//! Basic.Deliver is one going out, and a Basic.Nack or a Channel.Close carries
//! the reason something failed — which is usually why the capture was taken.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Type, channel, length — then the payload and a frame-end byte.
const HEADER: usize = 7;

/// Frame types (AMQP 0-9-1 §2.3).
const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;

/// Class and method identifiers (AMQP 0-9-1 §1.2). The pairs listed are the
/// ones that carry meaning for someone reading a capture rather than
/// implementing the protocol.
fn method_name(class: u16, method: u16) -> Option<&'static str> {
    Some(match (class, method) {
        (10, 10) => "Connection.Start",
        (10, 11) => "Connection.StartOk",
        (10, 30) => "Connection.Tune",
        (10, 31) => "Connection.TuneOk",
        (10, 40) => "Connection.Open",
        (10, 41) => "Connection.OpenOk",
        (10, 50) => "Connection.Close",
        (10, 51) => "Connection.CloseOk",
        (20, 10) => "Channel.Open",
        (20, 11) => "Channel.OpenOk",
        (20, 40) => "Channel.Close",
        (20, 41) => "Channel.CloseOk",
        (40, 10) => "Exchange.Declare",
        (40, 11) => "Exchange.DeclareOk",
        (40, 20) => "Exchange.Delete",
        (50, 10) => "Queue.Declare",
        (50, 11) => "Queue.DeclareOk",
        (50, 20) => "Queue.Bind",
        (50, 21) => "Queue.BindOk",
        (50, 30) => "Queue.Purge",
        (50, 40) => "Queue.Delete",
        (60, 10) => "Basic.Qos",
        (60, 20) => "Basic.Consume",
        (60, 21) => "Basic.ConsumeOk",
        (60, 30) => "Basic.Cancel",
        (60, 40) => "Basic.Publish (message in)",
        (60, 50) => "Basic.Return (undeliverable)",
        (60, 60) => "Basic.Deliver (message out)",
        (60, 70) => "Basic.Get",
        (60, 71) => "Basic.GetOk",
        (60, 72) => "Basic.GetEmpty (queue is empty)",
        (60, 80) => "Basic.Ack",
        (60, 90) => "Basic.Reject",
        (60, 120) => "Basic.Nack (rejected)",
        (85, 10) => "Confirm.Select",
        (90, 10) => "Tx.Select",
        (90, 20) => "Tx.Commit",
        (90, 30) => "Tx.Rollback",
        _ => return None,
    })
}

/// Dissect an AMQP segment (TCP 5672).
pub fn dissect_amqp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = describe(payload);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Amqp,
        summary,
    }
}

fn describe(payload: &[u8]) -> String {
    // The connection opens with a protocol header rather than a frame.
    if payload.starts_with(b"AMQP") && payload.len() >= 8 {
        return format!(
            "AMQP connection header (v{}.{}.{})",
            payload[4], payload[5], payload[6]
        );
    }
    if payload.len() < HEADER {
        return format!("AMQP ({})", super::bytes(payload.len() as u64));
    }
    let frame_type = payload[0];
    // The channel separates concurrent conversations on one connection, so it
    // is what tells two interleaved streams apart.
    let channel = u16::from_be_bytes([payload[1], payload[2]]);
    let size = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);

    match frame_type {
        FRAME_METHOD => {
            let Some(body) = payload.get(HEADER..HEADER + 4) else {
                return format!("AMQP method frame (channel {channel})");
            };
            let class = u16::from_be_bytes([body[0], body[1]]);
            let method = u16::from_be_bytes([body[2], body[3]]);
            match method_name(class, method) {
                Some(name) => format!("AMQP {name} (channel {channel})"),
                None => format!("AMQP method {class}.{method} (channel {channel})"),
            }
        }
        // A content header precedes the body and declares how large it is,
        // which is the message size a reader actually cares about.
        FRAME_HEADER => match payload.get(HEADER + 4..HEADER + 12) {
            Some(b) => {
                let body_size =
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                format!(
                    "AMQP content header (channel {channel}) — {} to follow",
                    super::bytes(body_size)
                )
            }
            None => format!("AMQP content header (channel {channel})"),
        },
        FRAME_BODY => format!(
            "AMQP content body (channel {channel}) — {}",
            super::bytes(size)
        ),
        FRAME_HEARTBEAT => "AMQP heartbeat".to_string(),
        other => format!("AMQP frame type {other} (channel {channel})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a method frame carrying the given class and method.
    fn method(channel: u16, class: u16, method: u16) -> Vec<u8> {
        let mut p = vec![FRAME_METHOD];
        p.extend_from_slice(&channel.to_be_bytes());
        p.extend_from_slice(&4u32.to_be_bytes());
        p.extend_from_slice(&class.to_be_bytes());
        p.extend_from_slice(&method.to_be_bytes());
        p.push(0xCE); // frame end
        p
    }

    #[test]
    fn the_opening_header_is_still_recognised() {
        let r = dissect_amqp(None, None, 50000, 5672, b"AMQP\x00\x00\x09\x01");
        assert_eq!(r.protocol, Protocol::Amqp);
        assert_eq!(r.summary, "AMQP connection header (v0.0.9)");
    }

    /// The direction a message is travelling is the thing worth seeing, and
    /// before this both read as undifferentiated queue traffic.
    #[test]
    fn publish_and_deliver_are_distinguished() {
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(1, 60, 40)).summary,
            "AMQP Basic.Publish (message in) (channel 1)"
        );
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(1, 60, 60)).summary,
            "AMQP Basic.Deliver (message out) (channel 1)"
        );
    }

    /// The failure paths explain why a capture was taken in the first place.
    #[test]
    fn rejections_and_closures_are_named() {
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(1, 60, 120)).summary,
            "AMQP Basic.Nack (rejected) (channel 1)"
        );
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(1, 60, 50)).summary,
            "AMQP Basic.Return (undeliverable) (channel 1)"
        );
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(0, 10, 50)).summary,
            "AMQP Connection.Close (channel 0)"
        );
    }

    /// A consumer polling an empty queue looks identical to a busy one unless
    /// this is named.
    #[test]
    fn an_empty_queue_is_visible() {
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(2, 60, 72)).summary,
            "AMQP Basic.GetEmpty (queue is empty) (channel 2)"
        );
    }

    /// One connection carries many channels, and the channel number is what
    /// separates two interleaved conversations.
    #[test]
    fn the_channel_distinguishes_concurrent_conversations() {
        assert!(dissect_amqp(None, None, 1, 5672, &method(7, 60, 40))
            .summary
            .ends_with("(channel 7)"));
    }

    /// The content header declares the message size before the body arrives.
    #[test]
    fn a_content_header_reports_the_message_size() {
        let mut p = vec![FRAME_HEADER];
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&14u32.to_be_bytes());
        p.extend_from_slice(&60u16.to_be_bytes()); // class
        p.extend_from_slice(&0u16.to_be_bytes()); // weight
        p.extend_from_slice(&2048u64.to_be_bytes()); // body size
        let r = dissect_amqp(None, None, 1, 5672, &p);
        assert_eq!(
            r.summary,
            "AMQP content header (channel 1) — 2048 bytes to follow"
        );
    }

    #[test]
    fn heartbeats_and_bodies_are_named() {
        let heartbeat = vec![FRAME_HEARTBEAT, 0, 0, 0, 0, 0, 0, 0xCE];
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &heartbeat).summary,
            "AMQP heartbeat"
        );
        let mut body = vec![FRAME_BODY];
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&512u32.to_be_bytes());
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &body).summary,
            "AMQP content body (channel 1) — 512 bytes"
        );
    }

    /// An unrecognised method still reports its numbers, which is how the
    /// specification refers to them anyway.
    #[test]
    fn an_unknown_method_reports_its_numbers() {
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &method(1, 99, 42)).summary,
            "AMQP method 99.42 (channel 1)"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &[FRAME_METHOD, 0, 1]).summary,
            "AMQP (3 bytes)"
        );
        // A method frame whose class and method were cut off.
        let short = vec![FRAME_METHOD, 0, 1, 0, 0, 0, 4];
        assert_eq!(
            dissect_amqp(None, None, 1, 5672, &short).summary,
            "AMQP method frame (channel 1)"
        );
    }
}
