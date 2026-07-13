use anyhow::Result;
use netscope_core::capture::CaptureEngine;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;

use crate::Cli;

pub fn run(cli: Cli) -> Result<()> {
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let mut capture = CaptureEngine::new();

    // Local interfaces, `-i -` (stdin stream), USBPcap devices or a remote
    // host over SSH — plus autostop and ring-buffer options.
    let label = crate::setup::start_capture(&cli, &mut capture, packet_tx)?;
    eprintln!("Capturing on: {label}");

    let use_json = cli.json;
    let mut names = NameCache::new();

    while let Ok(pkt) = packet_rx.recv() {
        names.observe(&pkt);
        if use_json {
            println!("{}", format_json(&pkt));
        } else {
            println!("{}", format_plain(&pkt, &names));
        }
    }

    capture.stop();
    Ok(())
}

fn format_plain(pkt: &Packet, names: &NameCache) -> String {
    let ts = pkt.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
    let src = match pkt.src_addr {
        Some(ip) => names.display_endpoint(ip, pkt.src_port),
        None => "??".into(),
    };
    let dst = match pkt.dst_addr {
        Some(ip) => names.display_endpoint(ip, pkt.dst_port),
        None => "??".into(),
    };
    format!(
        "[{ts}] {src} \u{2192} {dst}  {}  {}B  {}",
        pkt.protocol, pkt.length, pkt.summary
    )
}

fn format_json(pkt: &Packet) -> String {
    let ts = pkt.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let src = pkt.src_addr.map(|a| a.to_string());
    let dst = pkt.dst_addr.map(|a| a.to_string());
    format!(
        r#"{{"timestamp":"{}","src":{},"dst":{},"src_port":{},"dst_port":{},"protocol":"{}","length":{},"summary":"{}"}}"#,
        ts,
        src.map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".into()),
        dst.map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".into()),
        pkt.src_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".into()),
        pkt.dst_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".into()),
        pkt.protocol,
        pkt.length,
        escape_json(&pkt.summary),
    )
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use netscope_core::models::Protocol;

    fn pkt() -> Packet {
        Packet {
            timestamp: chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            src_addr: "192.168.1.10".parse().ok(),
            dst_addr: "1.1.1.1".parse().ok(),
            src_port: Some(50000),
            dst_port: Some(443),
            protocol: Protocol::Tls,
            length: 60,
            summary: "Client \"Hello\"".into(),
            data: bytes::Bytes::new(),
        }
    }

    #[test]
    fn plain_line_has_timestamp_endpoints_and_summary() {
        let line = format_plain(&pkt(), &NameCache::new());
        assert!(line.starts_with("[2026-01-02 03:04:05.000]"), "{line}");
        assert!(line.contains("192.168.1.10:50000 \u{2192} 1.1.1.1:443"));
        assert!(line.contains("TLS"));
        assert!(line.contains("60B"));
        assert!(line.ends_with("Client \"Hello\""));
    }

    #[test]
    fn plain_line_shows_placeholders_without_addresses() {
        let mut p = pkt();
        p.src_addr = None;
        p.dst_addr = None;
        let line = format_plain(&p, &NameCache::new());
        assert!(line.contains("?? \u{2192} ??"));
    }

    #[test]
    fn json_line_is_escaped_and_complete() {
        let out = format_json(&pkt());
        assert!(out.contains(r#""timestamp":"2026-01-02T03:04:05.000Z""#));
        assert!(out.contains(r#""src":"192.168.1.10""#));
        assert!(out.contains(r#""dst":"1.1.1.1""#));
        assert!(out.contains(r#""src_port":50000"#));
        assert!(out.contains(r#""dst_port":443"#));
        assert!(out.contains(r#""protocol":"TLS""#));
        assert!(out.contains(r#""length":60"#));
        // The quotes inside the summary are escaped, keeping the JSON valid.
        assert!(out.contains(r#""summary":"Client \"Hello\"""#));
    }

    #[test]
    fn json_line_uses_null_for_missing_fields() {
        let mut p = pkt();
        p.src_addr = None;
        p.src_port = None;
        let out = format_json(&p);
        assert!(out.contains(r#""src":null"#));
        assert!(out.contains(r#""src_port":null"#));
    }

    #[test]
    fn escape_json_handles_all_specials() {
        assert_eq!(escape_json("a\"b\\c\nd\re\tf"), "a\\\"b\\\\c\\nd\\re\\tf");
        assert_eq!(escape_json("plain"), "plain");
    }
}
