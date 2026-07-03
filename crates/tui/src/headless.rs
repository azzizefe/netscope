use anyhow::Result;
use netscope_core::capture::CaptureEngine;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;

use crate::Cli;

pub fn run(cli: Cli) -> Result<()> {
    let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
    let mut capture = CaptureEngine::new();
    let output_path = cli.write.as_deref();

    if let Some(iface) = cli.interface.as_deref() {
        capture.start_live(iface, cli.filter.as_deref(), output_path, packet_tx)?;
    } else if let Some(path) = cli.read.as_deref() {
        capture.start_offline(path, cli.filter.as_deref(), output_path, packet_tx)?;
    } else {
        let dev = netscope_core::capture::default_interface()?;
        eprintln!(
            "Capturing on: {}",
            netscope_core::capture::friendly_name(&dev)
        );
        capture.start_live(&dev.name, cli.filter.as_deref(), output_path, packet_tx)?;
    }

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
