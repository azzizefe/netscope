// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

pub struct TcpFlowState {
    pub max_seq: u32,
    pub last_ack: u32,
    pub last_win: u16,
    pub dup_ack_count: u32,
    pub seen_seqs: BTreeSet<u32>,
    pub last_was_pure_ack: bool,
}

use std::cell::RefCell;

thread_local! {
    static STATES: RefCell<HashMap<TcpFlowKey, TcpFlowState>> = RefCell::new(HashMap::new());
}

/// The TCP-segment fields flow analysis needs. Grouping them keeps
/// [`analyze_packet`]'s signature small and lets call sites name each field.
#[derive(Clone, Copy)]
pub struct TcpSegment {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub win: u16,
    pub payload_len: usize,
}

/// Analyze a TCP packet statefully to detect flow anomalies: Retransmissions, Duplicate ACKs, Out-of-Order.
/// Returns an optional warning string, e.g., `Some("[TCP Retransmission]")`.
pub fn analyze_packet(seg: TcpSegment) -> Option<String> {
    let TcpSegment {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        win,
        payload_len,
    } = seg;
    let src = src_ip?;
    let dst = dst_ip?;
    let key = TcpFlowKey {
        src_ip: src,
        src_port,
        dst_ip: dst,
        dst_port,
    };

    STATES.with(|states| {
        let mut guard = states.borrow_mut();
        let state = guard.entry(key).or_insert_with(|| TcpFlowState {
            max_seq: seq,
            last_ack: ack,
            last_win: win,
            dup_ack_count: 0,
            seen_seqs: BTreeSet::new(),
            last_was_pure_ack: false,
        });

        let mut result = None;

        let has_ack = flags & 0x10 != 0; // ACK flag
        let has_syn = flags & 0x02 != 0;
        let has_fin = flags & 0x01 != 0;
        let has_rst = flags & 0x04 != 0;

        let is_pure_ack = payload_len == 0 && has_ack && !has_syn && !has_fin && !has_rst;

        if payload_len > 0 {
            if state.seen_seqs.contains(&seq) {
                result = Some("[TCP Retransmission]".to_string());
            } else if seq < state.max_seq {
                result = Some("[TCP Out-of-Order]".to_string());
            }
            state.seen_seqs.insert(seq);
            if seq > state.max_seq {
                state.max_seq = seq;
            }
            state.last_was_pure_ack = false;
        } else if is_pure_ack {
            if state.last_was_pure_ack && ack == state.last_ack && win == state.last_win {
                state.dup_ack_count += 1;
                result = Some(format!("[TCP Dup ACK #{}]", state.dup_ack_count));
            } else {
                state.dup_ack_count = 0;
            }
            state.last_was_pure_ack = true;
        }

        state.last_ack = ack;
        state.last_win = win;

        result
    })
}

pub fn clear_tcp_states() {
    STATES.with(|states| states.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_retransmission_and_dup_ack() {
        clear_tcp_states();
        let ip_a = Some("10.0.0.1".parse().unwrap());
        let ip_b = Some("10.0.0.2".parse().unwrap());

        // A data segment; individual tests override seq/flags/payload_len.
        let base = TcpSegment {
            src_ip: ip_a,
            dst_ip: ip_b,
            src_port: 59999,
            dst_port: 9999,
            seq: 1000,
            ack: 1,
            flags: 0x18,
            win: 1024,
            payload_len: 100,
        };

        // First packet with payload
        let r1 = analyze_packet(base);
        assert!(r1.is_none());

        // Retransmission of the same seq
        let r2 = analyze_packet(base);
        assert_eq!(r2, Some("[TCP Retransmission]".to_string()));

        // Out of order packet
        let r3 = analyze_packet(TcpSegment { seq: 500, ..base });
        assert_eq!(r3, Some("[TCP Out-of-Order]".to_string()));

        // Dup ACK (pure ACK: no payload, ACK flag only)
        let pure_ack = TcpSegment {
            seq: 1100,
            flags: 0x10,
            payload_len: 0,
            ..base
        };
        let d1 = analyze_packet(pure_ack);
        assert!(d1.is_none());
        let d2 = analyze_packet(pure_ack);
        assert_eq!(d2, Some("[TCP Dup ACK #1]".to_string()));
    }
}
