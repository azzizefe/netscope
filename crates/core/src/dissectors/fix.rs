// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// FIX fields are delimited by SOH (0x01).
const SOH: u8 = 0x01;

/// Structural check: a FIX message always begins with `8=FIX` (tag 8,
/// BeginString). FIX runs on negotiated ports, so it's recognised by content.
pub fn looks_like_fix(p: &[u8]) -> bool {
    p.starts_with(b"8=FIX")
}

/// Name the FIX MsgType (tag 35) value — the common ones traders care about.
fn msg_type_name(v: &str) -> &'static str {
    match v {
        "0" => "Heartbeat",
        "A" => "Logon",
        "5" => "Logout",
        "D" => "NewOrderSingle",
        "F" => "OrderCancelRequest",
        "8" => "ExecutionReport",
        "W" => "MarketDataSnapshot",
        "V" => "MarketDataRequest",
        _ => "message",
    }
}

/// Dissect a FIX message — the protocol financial exchanges and trading systems
/// use for orders and market data. Tag 8 is the version, tag 35 the message
/// type (FIX 4.x / FIXT).
pub fn dissect_fix(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(256)]);
    let field = |tag: &str| -> Option<String> {
        text.split(SOH as char)
            .find_map(|f| f.strip_prefix(tag).map(|v| v.to_string()))
    };
    let version = field("8=").unwrap_or_else(|| "FIX".to_string());
    let summary = match field("35=") {
        Some(mt) => format!("FIX {version} — {}", msg_type_name(&mt)),
        None => format!("FIX {version}"),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fix,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_order() {
        let msg = b"8=FIX.4.2\x0135=D\x0149=CLIENT\x0156=BROKER\x01";
        assert!(looks_like_fix(msg));
        let r = dissect_fix(None, None, 40000, 5001, msg);
        assert_eq!(r.protocol, Protocol::Fix);
        assert_eq!(r.summary, "FIX FIX.4.2 — NewOrderSingle");
    }
}
