// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// OVSDB methods (RFC 7047 §4). The interesting split is between reading the
/// schema, watching for changes, and actually altering the switch.
fn method_note(method: &str) -> Option<&'static str> {
    Some(match method {
        "list_dbs" => "listing databases",
        "get_schema" => "fetching the schema",
        "transact" => "changing the switch",
        "cancel" => "cancelling a transaction",
        "monitor" | "monitor_cond" | "monitor_cond_since" => "subscribing to changes",
        "update" | "update2" | "update3" => "reporting a change",
        "monitor_cancel" => "unsubscribing",
        "lock" | "steal" | "unlock" => "coordinating writers",
        "locked" | "stolen" => "lock notification",
        "echo" => "keepalive",
        _ => return None,
    })
}

/// Pull a top-level string field out of a JSON object without a full parse.
///
/// The message is JSON-RPC, so the fields we want are near the front and quoted
/// plainly. A real parser would be overkill here and would have to cope with a
/// message split across TCP segments; this reads what is present.
fn json_string_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let at = text.find(&needle)? + needle.len();
    let rest = text.get(at..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Dissect an OVSDB message — the management protocol for Open vSwitch, on
/// TCP 6640, and OVN's northbound and southbound databases on 6641 and 6642
/// (RFC 7047).
///
/// Recognition is by port alone. The messages are JSON-RPC, and a JSON object
/// is far too common a shape on the wire to claim traffic on the strength of.
///
/// Open vSwitch is the switch inside most OpenStack and container hosts. OVSDB
/// is how its configuration is read and changed: which ports exist, which
/// bridges they belong to, what the tunnels point at. A transaction is the
/// message that actually alters the switch, so it is the one worth spotting.
pub fn dissect_ovsdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let head = &payload[..payload.len().min(512)];
    let summary = match std::str::from_utf8(head) {
        Ok(text) => match json_string_field(text, "method") {
            Some(method) => match method_note(method) {
                Some(note) => format!("OVSDB {method} — {note}"),
                None => format!("OVSDB {}", super::truncate(method, 32)),
            },
            // A reply carries a result rather than a method.
            None if text.contains("\"result\"") => "OVSDB reply".to_string(),
            None if text.contains("\"error\"") => "OVSDB error".to_string(),
            None => format!("OVSDB ({})", super::bytes(payload.len() as u64)),
        },
        Err(_) => format!("OVSDB ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ovsdb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str) -> Vec<u8> {
        format!(r#"{{"id":0,"method":"{method}","params":["Open_vSwitch"]}}"#).into_bytes()
    }

    #[test]
    fn transaction_is_the_one_that_changes_things() {
        let r = dissect_ovsdb(None, None, 40000, 6640, &request("transact"));
        assert_eq!(r.protocol, Protocol::Ovsdb);
        assert_eq!(r.summary, "OVSDB transact — changing the switch");
    }

    #[test]
    fn reads_and_subscriptions_are_distinguished() {
        assert_eq!(
            dissect_ovsdb(None, None, 1, 6640, &request("get_schema")).summary,
            "OVSDB get_schema — fetching the schema"
        );
        assert_eq!(
            dissect_ovsdb(None, None, 1, 6640, &request("monitor_cond")).summary,
            "OVSDB monitor_cond — subscribing to changes"
        );
        assert_eq!(
            dissect_ovsdb(None, None, 1, 6640, &request("update3")).summary,
            "OVSDB update3 — reporting a change"
        );
    }

    /// A reply has no method field, so it has to be recognised by its result.
    #[test]
    fn replies_and_errors_are_recognised() {
        let reply = br#"{"id":0,"result":[{"db":"Open_vSwitch"}],"error":null}"#;
        assert_eq!(
            dissect_ovsdb(None, None, 6640, 1, reply).summary,
            "OVSDB reply"
        );
        let err = br#"{"id":0,"error":{"details":"no such table"}}"#;
        assert_eq!(
            dissect_ovsdb(None, None, 6640, 1, err).summary,
            "OVSDB error"
        );
    }

    #[test]
    fn unknown_method_still_reports_its_name() {
        let r = dissect_ovsdb(None, None, 1, 6640, br#"{"method":"custom_op","id":1}"#);
        assert_eq!(r.summary, "OVSDB custom_op");
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let r = dissect_ovsdb(None, None, 1, 6640, &[0xFF, 0xFE, 0xFD]);
        assert_eq!(r.summary, "OVSDB (3 bytes)");
    }
}
