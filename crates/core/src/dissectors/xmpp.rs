// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an XMPP message (TCP 5222) — the Jabber instant-messaging protocol,
/// an XML stream. Stanzas are `<message>`, `<presence>` and `<iq>` (RFC 6120).
pub fn dissect_xmpp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(256)]);
    let t = text.trim_start();
    let summary = if t.contains("<stream:stream") || t.contains("<stream ") {
        "XMPP — stream open".to_string()
    } else if t.starts_with("<message") {
        "XMPP message".to_string()
    } else if t.starts_with("<presence") {
        "XMPP presence".to_string()
    } else if t.starts_with("<iq") {
        "XMPP iq (info/query)".to_string()
    } else if t.starts_with("<?xml") || t.starts_with('<') {
        "XMPP XML stream".to_string()
    } else {
        format!("XMPP ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Xmpp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_open() {
        let r = dissect_xmpp(
            None,
            None,
            40000,
            5222,
            b"<stream:stream xmlns='jabber:client'>",
        );
        assert_eq!(r.protocol, Protocol::Xmpp);
        assert_eq!(r.summary, "XMPP — stream open");
    }

    #[test]
    fn message_stanza() {
        let r = dissect_xmpp(
            None,
            None,
            40000,
            5222,
            b"<message to='a@b'><body>hi</body></message>",
        );
        assert_eq!(r.summary, "XMPP message");
    }
}
