// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//
// These were unit tests inside `src/lib.rs`. They live here because of how the
// Windows manifest reaches a test binary: `build.rs` has to link the resource
// archive a second time, and the only cargo scope that reaches a *lib's* unit
// tests is the unscoped `rustc-link-arg`, which also hits the bin — where
// tauri-build has already linked the same archive. GNU ld drops the duplicate;
// MSVC's CVTRES calls it fatal (CVT1100) and the app does not link at all.
// As integration tests they are covered by `rustc-link-arg-tests`, which the
// bin does not see, so every target gets exactly one copy on both toolchains.
//
// The cost is that everything they call has to be `pub`. Plain helpers and the
// structs they return simply became public; the `#[tauri::command]`s could not,
// because at the crate root the macro's own `pub use __cmd__name` collides with
// the macro it re-exports (E0255), so they are reached through the thin
// `testing` wrappers instead. Nothing else consumes this lib — the crate exists
// to be the desktop app — so the wider surface buys a linkable Windows build.

use netscope_core::models::Packet;
use netscope_desktop_lib::testing::{
    arp_scan, block_ip, escalation_off, get_alert_rules, get_glossary, get_lessons,
    get_protocol_risk, is_elevated, list_blocked, list_interfaces, list_plugins, protocol_count,
    protocol_table, replay_packet, save_object, tls_keylog_clear, tls_keylog_load,
    tls_keylog_status, unblock_ip,
};
use netscope_desktop_lib::{
    active_escalations, build_pcap_bytes, build_pcapng_bytes, encode_capture, english_name,
    notification_channels, wants_pcapng, NotificationChannelInfo,
};
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn replay_tcp_roundtrips_against_echo_server() {
    // Local echo server: read a line, write it back, close.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = sock.read(&mut buf) {
                let _ = sock.write_all(&buf[..n]);
            }
        }
    });

    let res = replay_packet(
        "127.0.0.1".into(),
        port,
        "tcp".into(),
        b"ping".to_vec(),
        Some(1000),
    )
    .expect("replay should succeed");

    assert_eq!(res.sent, 4);
    assert_eq!(res.response, b"ping");
    assert!(!res.truncated);
}

#[test]
fn replay_rejects_unknown_protocol() {
    let err = replay_packet(
        "127.0.0.1".into(),
        80,
        "icmp".into(),
        vec![1, 2, 3],
        Some(200),
    )
    .unwrap_err();
    assert!(err.contains("Unsupported protocol"));
}

/// The frontend groups flows and labels them from this table, so every
/// protocol has to be in it. It used to answer both questions from lists
/// written into its own source that covered about forty names — a flow
/// carrying PROFINET or NGAP was labelled TCP because neither was listed.
#[test]
fn the_protocol_table_covers_the_whole_registry() {
    use netscope_core::models::Protocol;

    let table = protocol_table();
    let named = Protocol::ALL
        .iter()
        .filter(|p| !p.display_name().is_empty())
        .count();
    assert_eq!(table.len(), named, "every named protocol must be present");
    assert!(table.len() > 2000, "got {} rows", table.len());

    // The transports the frontend switches on, and nothing else.
    for (name, meta) in &table {
        assert!(
            matches!(meta.transport, "tcp" | "udp" | "icmp" | "arp" | "other"),
            "{name} has transport {:?}",
            meta.transport
        );
    }

    // Spot-check the two ends: a protocol the old lists knew, and one they
    // did not. Both must outrank the bare transport they ride on.
    let http = &table["HTTP"];
    assert_eq!(http.transport, "tcp");
    assert!(http.rank > table["TCP"].rank);

    let profinet = &table["PROFINET"];
    assert_eq!(profinet.transport, "other");
    assert!(
        profinet.rank > table["TCP"].rank,
        "PROFINET must be able to name its own flow"
    );
}

/// The two answer different questions and must not be conflated.
///
/// `protocol_count` is a claim shown to the user, so it counts only what a
/// capture can contain. `protocol_table` is a lookup the frontend consults
/// for a protocol it has *already* received, so it must answer for every
/// row — including ones only a future dissector will produce. This asserted
/// they were equal, which forced the displayed count to include ~1,900
/// protocols netscope cannot see.
#[test]
fn protocol_count_is_the_produced_subset_of_the_table() {
    use netscope_core::models::Protocol;
    let count = protocol_count();
    let table = protocol_table();
    assert_eq!(count, Protocol::produced().len());
    assert!(
        count < table.len(),
        "every row is marked produced ({count}) — did the status field collapse?"
    );
    // The lookup must still cover the protocols the count advertises.
    for p in Protocol::produced() {
        let name = p.display_name();
        if !name.is_empty() {
            assert!(table.contains_key(name), "{name} missing from the lookup");
        }
    }
}

#[test]
fn glossary_contains_common_terms() {
    let glossary = get_glossary();
    assert!(!glossary.is_empty());
    assert!(glossary.iter().any(|e| e.term == "IP address"));
}

#[test]
fn protocol_risk_known_protocol() {
    let risk = get_protocol_risk("HTTP".to_string()).unwrap();
    assert!(!risk.severity.is_empty());
}

/// The Learn tab is fed entirely from `education.rs`. This used to be a
/// hand-written array of 53 pairs that silently stopped growing as
/// protocols were added, so the guard is that the command still returns
/// everything `education.rs` has rather than a frozen subset of it.
#[test]
fn lessons_cover_every_protocol_that_has_one() {
    let lessons = get_lessons();
    let expected = netscope_core::education::protocols_with_lessons().len();

    assert_eq!(lessons.len(), expected, "every lesson must reach the UI");
    assert!(
        lessons.len() > 53,
        "got {} — back to the old hand-written list",
        lessons.len()
    );

    // A lesson with an empty title or body renders as a blank card.
    for l in &lessons {
        assert!(!l.protocol.is_empty(), "lesson with no protocol name");
        assert!(!l.title.is_empty(), "{} has no title", l.protocol);
        assert!(!l.summary.is_empty(), "{} has no summary", l.protocol);
    }
}

/// The rules the app ships with have to be rules the engine can actually
/// act on. Both halves of this fail silently: `AlertEngine::check` matches
/// `trigger_type` as a string and falls through `_ => {}` on anything it
/// does not know, and a filter that will not parse can never match a
/// packet. Either way the rule sits in the UI looking armed and never fires.
#[test]
fn default_alert_rules_are_ones_the_engine_can_fire() {
    use netscope_core::filter::Filter;

    // The arms `AlertEngine::check` actually handles.
    const HANDLED: &[&str] = &[
        "threshold",
        "anomaly",
        "time-based",
        "signature",
        "correlation",
        "absence",
    ];

    let rules = get_alert_rules();
    assert!(!rules.is_empty(), "the app must ship some default rules");

    for rule in &rules {
        assert!(!rule.name.is_empty(), "a default rule has no name");
        assert!(
            HANDLED.contains(&rule.trigger.trigger_type.as_str()),
            "rule {:?} has trigger_type {:?}, which the engine ignores",
            rule.name,
            rule.trigger.trigger_type,
        );
        // The set documented on `AlertRule::severity`. Pinned to that list
        // on purpose: a severity outside it is one the UI cannot style, and
        // widening this without widening the doc is how they drift apart.
        assert!(
            matches!(
                rule.severity.as_str(),
                "informational" | "low" | "medium" | "high"
            ),
            "rule {:?} has severity {:?}",
            rule.name,
            rule.severity,
        );
        // An empty filter means "every packet" and is not passed to the
        // parser; anything else has to compile.
        if !rule.trigger.filter.is_empty() {
            assert!(
                Filter::parse(&rule.trigger.filter).is_ok(),
                "rule {:?} has an unparseable filter {:?}",
                rule.name,
                rule.trigger.filter,
            );
        }
    }
}

/// A channel is "configured" only when its settings are actually present.
///
/// This guards against what the view used to do: five rows of markup with
/// fixed badges, so Syslog read "Active" on a machine with nothing set up.
/// Every badge now has to be derivable from `[notifications]`, so a default
/// config must report nothing as configured.
#[test]
fn channel_status_is_read_from_config_not_assumed() {
    use netscope_core::config::Notifications;

    let empty = Notifications::default();
    for c in notification_channels(&empty) {
        if c.id == "winevent" {
            // The one channel with nothing to configure: it depends on the
            // platform, not on settings.
            assert_eq!(c.configured, cfg!(target_os = "windows"));
            continue;
        }
        assert!(!c.configured, "{} claims to be configured by default", c.id);
        assert!(
            c.detail.contains("notifications."),
            "{} should name the missing setting, got {:?}",
            c.id,
            c.detail,
        );
    }

    let mut set = Notifications {
        syslog_host: "10.0.0.9".into(),
        slack_webhook_url: "https://hooks.example/abc".into(),
        email_smtp_host: "smtp.example".into(),
        email_to: "soc@example".into(),
        // Deliberately only half of Telegram: one field cannot deliver.
        telegram_token: "secret-token".into(),
        ..Default::default()
    };
    let configured = |cs: &[NotificationChannelInfo], id: &str| {
        cs.iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("channel {id} missing"))
            .configured
    };

    let cs = notification_channels(&set);
    assert!(configured(&cs, "syslog"));
    assert!(configured(&cs, "slack"));
    assert!(configured(&cs, "email"));
    assert!(!configured(&cs, "telegram"), "a token alone cannot deliver");

    set.telegram_chat_id = "12345".into();
    assert!(configured(&notification_channels(&set), "telegram"));

    // Tokens and webhook URLs are credentials; only their presence is
    // reported, so they must not travel to the UI in `detail`.
    for c in notification_channels(&set) {
        assert!(
            !c.detail.contains("secret-token"),
            "leaked token in {}",
            c.id
        );
        assert!(
            !c.detail.contains("hooks.example"),
            "leaked webhook in {}",
            c.id
        );
    }
}

/// Blank and whitespace-only settings must read as absent, so the engine's
/// own "not configured" checks stay the single source of truth.
#[test]
fn blank_notification_settings_become_none() {
    use netscope_core::config::Notifications;

    let blanks = Notifications {
        syslog_host: "   ".into(),
        slack_webhook_url: String::new(),
        telegram_token: "\t".into(),
        ..Default::default()
    };
    let cfg = blanks.to_engine_config();
    assert!(cfg.syslog_host.is_none());
    assert!(cfg.slack_webhook_url.is_none());
    assert!(cfg.telegram_token.is_none());

    let padded = Notifications {
        syslog_host: "  10.0.0.9  ".into(),
        ..Default::default()
    };
    assert_eq!(
        padded.to_engine_config().syslog_host.as_deref(),
        Some("10.0.0.9"),
        "surrounding whitespace must not reach the socket",
    );
}

/// `tls_keylog_*` are thin wrappers whose only real job is mapping the core
/// stats onto the fields the UI reads. A swap of `added`/`rejected` would
/// report every accepted secret as junk, so both counts are pinned here.
///
/// Kept as one test on purpose: the key log is process-global, so splitting
/// this would let the parts race each other inside the test binary.
#[test]
fn keylog_load_reports_accepted_and_rejected_then_clears() {
    // `CLIENT_RANDOM <64 hex> <96 hex>` — two well-formed lines, plus a
    // comment (ignored outright) and two malformed ones.
    let good = format!(
        "CLIENT_RANDOM {} {}\nCLIENT_RANDOM {} {}\n",
        "a".repeat(64),
        "b".repeat(96),
        "c".repeat(64),
        "d".repeat(96),
    );
    // Deliberately 2 accepted vs 3 rejected: with equal counts a swap of the
    // two fields still satisfies both assertions and the test proves nothing.
    let text = format!(
        "# comment line\n{good}\
         CLIENT_RANDOM tooshort ff\n\
         not a keylog line\n\
         CLIENT_RANDOM {} nothex!!\n",
        "e".repeat(64),
    );

    let loaded = tls_keylog_load(text);
    assert_eq!(loaded.added, 2, "both well-formed secrets must be accepted");
    assert_eq!(
        loaded.rejected, 3,
        "the three malformed lines must be counted"
    );

    // `status` reports the live session count and never invents a delta.
    let status = tls_keylog_status();
    assert_eq!(status.sessions, loaded.sessions);
    assert_eq!(status.added, 0);
    assert_eq!(status.rejected, 0);

    // These secrets decrypt real traffic — clearing has to actually clear.
    let cleared = tls_keylog_clear();
    assert_eq!(cleared.sessions, 0);
    assert_eq!(
        tls_keylog_status().sessions,
        0,
        "secrets survived a clear()"
    );
}

#[test]
fn protocol_risk_unknown_returns_none() {
    let risk = get_protocol_risk("NONEXISTENT_PROTOCOL_XYZ".to_string());
    assert!(risk.is_none());
}

#[test]
fn save_object_writes_to_disk() {
    let dir = std::env::temp_dir().join("netscope-test-save-object");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.bin");
    let path_str = path.to_string_lossy().into_owned();

    let result = save_object(path_str, vec![1, 2, 3, 4, 5]);
    assert!(result.is_ok());

    let read_back = std::fs::read(&path).unwrap();
    assert_eq!(read_back, vec![1, 2, 3, 4, 5]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_object_reports_io_error() {
    let bogus = format!("Z:\\{}\0", std::process::id());
    let result = save_object(bogus, vec![]);
    assert!(result.is_err());
}

#[test]
fn list_plugins_returns_vec() {
    let plugins = list_plugins();
    // plugins() reads from a directory — it may be empty, but it must be a
    // valid Vec<PluginInfo> with sensible defaults for every entry.
    for p in &plugins {
        assert!(!p.name.is_empty());
        assert!(matches!(p.transport.as_str(), "tcp" | "udp"));
        assert!(!p.description.is_empty());
    }
}

#[test]
fn is_elevated_returns_bool() {
    // Whether this process is elevated depends on how it was launched, so
    // there is no value to assert. What matters is that the probe returns
    // rather than panicking — on Windows it shells out to `whoami /groups`.
    //
    // This used to read `assert!(elevated == true || elevated == false)`,
    // which is a tautology for a `bool`: the test could not fail even if
    // the function were replaced by one that always returned false.
    let elevated = is_elevated();
    assert_eq!(
        elevated,
        netscope_core::firewall::is_elevated(),
        "the command must report the same privilege state as the core probe",
    );
}

#[test]
fn build_pcap_bytes_produces_valid_header() {
    use std::io::{Cursor, Read};

    let packet = Packet {
        timestamp: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: netscope_core::models::Protocol::Tcp,
        length: 4,
        summary: "test".into(),
        data: b"ping"[..].into(),
        llm: None,
    };
    let bytes = build_pcap_bytes(&[packet]);

    let mut r = Cursor::new(&bytes);
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    assert_eq!(u32::from_le_bytes(buf), 0xa1b2c3d4, "pcap magic");
    assert_eq!(
        bytes.len(),
        24 + 16 + 4,
        "global header + rec header + payload"
    );
}

#[test]
fn build_pcapng_bytes_produces_valid_block() {
    use std::io::{Cursor, Read};

    let packet = Packet {
        timestamp: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: netscope_core::models::Protocol::Udp,
        length: 3,
        summary: "test".into(),
        data: b"abc"[..].into(),
        llm: None,
    };
    let bytes = build_pcapng_bytes(&[packet]).unwrap();

    let mut r = Cursor::new(&bytes);
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0x0A, 0x0D, 0x0D, 0x0A], "pcapng SHB magic");
}

#[test]
fn block_unblock_ip_workflow() {
    let ip = "192.168.1.240";
    let _ = unblock_ip(ip.into());
    let initial_blocked = list_blocked();
    assert!(!initial_blocked.contains(&ip.to_string()));

    let err = block_ip("invalid-ip".into()).unwrap_err();
    assert!(err.contains("not a valid IP address"));

    let unblock_err = unblock_ip("invalid-ip".into()).unwrap_err();
    assert!(unblock_err.contains("not a valid IP address"));
}

/// Whatever adapters this machine has, the list the frontend receives must
/// be well-formed: every row selectable by a unique name, and every `kind`
/// one the UI knows how to render.
///
/// An empty list is a legitimate result — a machine with no capture driver
/// installed has no interfaces — so this asserts the *shape* of each row
/// rather than that any exist. Verifying real enumeration needs a real
/// adapter; that is recorded in `UNTESTED.md`.
#[test]
fn every_listed_interface_is_selectable_and_classified() {
    const KINDS: [&str; 5] = ["ethernet", "loopback", "usb", "bluetooth", "can"];

    let interfaces = list_interfaces().expect("interface enumeration should succeed");
    let mut names = std::collections::HashSet::new();
    for iface in &interfaces {
        assert!(
            !iface.name.is_empty(),
            "an interface with no name cannot be selected"
        );
        assert!(
            KINDS.contains(&iface.kind.as_str()),
            "unknown interface kind {:?} — the UI has no icon for it",
            iface.kind
        );
        assert!(
            names.insert(iface.name.clone()),
            "duplicate interface name {:?}: selecting one would start the other",
            iface.name
        );
    }
}

/// "Off" has two causes and they must not be described with each other's
/// message.
///
/// `build_escalation_engine` returns `None` both for `enabled = false` and
/// for `enabled = true` with an empty rota. The second is the dangerous
/// one — escalation is switched on and will page nobody — and the only
/// thing that tells the two apart in the UI is this string.
#[test]
fn a_switched_on_but_empty_rota_says_so() {
    let empty_rota = escalation_off(true, 31);
    assert!(!empty_rota.enabled);
    assert!(
        empty_rota.reason.contains("escalation.oncall"),
        "an enabled-but-empty rota must point at the empty list, got: {}",
        empty_rota.reason
    );

    let switched_off = escalation_off(false, 31);
    assert!(
        switched_off.reason.contains("enabled = true"),
        "a disabled escalation must say how to turn it on, got: {}",
        switched_off.reason
    );

    assert_ne!(
        empty_rota.reason, switched_off.reason,
        "the two causes must not read the same"
    );
    assert_eq!(empty_rota.iso_week, 31, "the week is reported either way");
}

/// Open escalations come back oldest first, and one that has run off the
/// end of the chain is still listed.
#[test]
fn open_escalations_are_oldest_first_and_never_dropped() {
    use netscope_core::escalation::{ActiveEscalation, EscalationEngine};

    let now = chrono::Utc::now();
    let mut engine = EscalationEngine::new(Default::default());
    let chain_len = engine.default_policy.chain.len();

    let mut add = |id: &str, age_mins: i64, step: usize| {
        engine.active_escalations.insert(
            id.to_string(),
            ActiveEscalation {
                alert_id: id.to_string(),
                rule_name: "rule".into(),
                alert_msg: "msg".into(),
                start_time: now - chrono::Duration::minutes(age_mins),
                current_step_index: step,
                last_escalated: now,
                status: "Escalating".into(),
            },
        );
    };
    add("recent", 5, 0);
    add("oldest", 90, chain_len); // past the last rung
    add("middle", 40, 1);

    let listed = active_escalations(&engine, now);
    let ids: Vec<&str> = listed.iter().map(|e| e.alert_id.as_str()).collect();
    assert_eq!(
        ids,
        ["oldest", "middle", "recent"],
        "the longest-unanswered alert must come first"
    );
    assert_eq!(
        listed[0].level, "Top",
        "an escalation past the last step has nowhere higher to go, and must \
         still be shown"
    );
    assert!(listed[0].age_secs >= 90 * 60);
}

/// The file name decides the format, and both save paths must read it the
/// same way.
///
/// They did not: `save_pcap` keyed on `.pcapng`, `save_pcap_encrypted` on
/// `.pcapng.enc`. Saving an encrypted capture as `session.pcapng` therefore
/// wrote classic pcap bytes under a pcapng name — a file that encrypts,
/// writes and decrypts without complaint, and is only found to be the wrong
/// format by whatever opens it afterwards.
#[test]
fn the_extension_picks_the_format_the_same_way_encrypted_or_not() {
    for name in [
        "session.pcapng",
        "session.pcapng.enc",
        "SESSION.PCAPNG",
        "SESSION.PCAPNG.ENC",
        "/tmp/a.b.c/session.pcapng.enc",
    ] {
        assert!(wants_pcapng(name), "{name} should be written as pcapng");
    }
    for name in [
        "session.pcap",
        "session.pcap.enc",
        "session",
        "pcapng.pcap",
        "session.pcapng.gz",
    ] {
        assert!(!wants_pcapng(name), "{name} should be written as pcap");
    }
}

/// The bytes must match the format the name promised, and an empty buffer
/// must be refused rather than written as a zero-packet file the user
/// mistakes for their capture.
#[test]
fn encode_capture_writes_the_format_the_name_promises() {
    let packet = Packet {
        timestamp: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: netscope_core::models::Protocol::Tcp,
        length: 4,
        summary: "test".into(),
        data: b"ping"[..].into(),
        llm: None,
    };

    let pcapng = encode_capture(std::slice::from_ref(&packet), "session.pcapng.enc").unwrap();
    assert_eq!(
        &pcapng[..4],
        &[0x0A, 0x0D, 0x0D, 0x0A],
        "an encrypted .pcapng must still be pcapng underneath"
    );

    let pcap = encode_capture(std::slice::from_ref(&packet), "session.pcap.enc").unwrap();
    assert_eq!(
        &pcap[..4],
        &[0xD4, 0xC3, 0xB2, 0xA1],
        "a .pcap must be classic pcap"
    );

    let err = encode_capture(&[], "session.pcap")
        .expect_err("an empty buffer is nothing to save, not an empty file");
    assert!(
        err.contains("No captured packets"),
        "unexpected error: {err}"
    );
}

/// Scanning an interface that does not exist must fail, not answer.
///
/// The previous version of this test asserted
/// `invalid.is_ok() || invalid.is_err()` — true of every `Result` ever
/// constructed — because the behaviour underneath was itself undecided:
/// `discover::interface_ipv4` fell back to the first adapter with a
/// routable address, so an unknown name returned a neighbour list for
/// some other subnet. Both are fixed; this pins the result.
///
/// The `"__all__"` path is deliberately not exercised here: it sends UDP
/// probes across the live subnet and sleeps 1.5s, which is a side effect,
/// not a test.
#[test]
fn arp_scan_refuses_an_unknown_interface() {
    let err = arp_scan("nonexistent_iface_xyz_999".into())
        .expect_err("an interface that does not exist has no neighbours to report");
    assert!(
        err.contains("routable IPv4"),
        "the error should say why nothing was scanned, got: {err}"
    );
}

#[test]
fn notification_channels_lists_all_targets() {
    let channels = notification_channels(&netscope_core::config::Notifications::default());
    assert_eq!(channels.len(), 5);

    let ids: Vec<&str> = channels.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"syslog"));
    assert!(ids.contains(&"email"));
    assert!(ids.contains(&"slack"));
    assert!(ids.contains(&"telegram"));
    assert!(ids.contains(&"winevent"));
}

#[test]
fn encrypted_pcap_validation_flow() {
    let packet = Packet {
        timestamp: chrono::Utc::now(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: netscope_core::models::Protocol::Tcp,
        length: 4,
        summary: "test".into(),
        data: b"ping"[..].into(),
        llm: None,
    };
    let plain_bytes = build_pcap_bytes(&[packet]);
    assert!(!netscope_core::crypto::is_encrypted(&plain_bytes));

    let sealed = netscope_core::crypto::encrypt(&plain_bytes, "secret-pass").unwrap();
    assert!(netscope_core::crypto::is_encrypted(&sealed));

    let decrypted = netscope_core::crypto::decrypt(&sealed, "secret-pass").unwrap();
    assert_eq!(decrypted, plain_bytes);

    let bad_pass = netscope_core::crypto::decrypt(&sealed, "wrong-pass");
    assert!(bad_pass.is_err());
}

#[test]
fn english_name_helper_extracts_name() {
    let names = maxminddb::geoip2::Names {
        english: Some("Turkey"),
        german: None,
        spanish: None,
        french: None,
        japanese: None,
        brazilian_portuguese: None,
        russian: None,
        simplified_chinese: None,
    };
    assert_eq!(english_name(&names), Some("Turkey".into()));

    let empty_names = maxminddb::geoip2::Names {
        english: None,
        german: None,
        spanish: None,
        french: None,
        japanese: None,
        brazilian_portuguese: None,
        russian: None,
        simplified_chinese: None,
    };
    assert_eq!(english_name(&empty_names), None);
}
