use std::path::Path;

use netscope_core::capture::{CaptureEngine, CaptureOptions, StopConditions};
use netscope_core::models::{Packet, Protocol};

/// Root of the fixture pcap files (workspace-root / fixtures/).
fn fixtures() -> &'static Path {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/");
    Path::new(dir)
}

/// Run a pcap file through the full engine pipeline and collect packets.
fn run_pcap(path: &Path) -> Vec<Packet> {
    let mut eng = CaptureEngine::new();
    let (tx, rx) = crossbeam_channel::unbounded();
    eng.start_offline(path.to_str().unwrap(), None, None, tx)
        .expect("start_offline should succeed");
    let packets: Vec<Packet> = rx.iter().collect();
    eng.stop();
    packets
}

/// Run a pcap file with a stop condition (packet count limit).
fn run_pcap_with_limit(path: &Path, n: u64) -> Vec<Packet> {
    let mut eng = CaptureEngine::new();
    let (tx, rx) = crossbeam_channel::unbounded();
    let opts = CaptureOptions {
        stop: StopConditions {
            packets: Some(n),
            ..Default::default()
        },
        ..Default::default()
    };
    eng.start_read_stream(
        Box::new(std::fs::File::open(path).unwrap()),
        "test",
        &opts,
        tx,
    )
    .expect("start_read_stream should succeed");
    let packets: Vec<Packet> = rx.iter().collect();
    eng.stop();
    packets
}

// ── Single-frame pcap files ──────────────────────────────────────────

#[test]
fn pcap_http_request() {
    let packets = run_pcap(&fixtures().join("http_request.pcap"));
    assert_eq!(
        packets.len(),
        1,
        "http_request.pcap should contain 1 packet"
    );
    assert_eq!(packets[0].protocol, Protocol::Http);
    assert!(packets[0].summary.contains("GET") || packets[0].summary.contains("HTTP"));
    assert_eq!(packets[0].src_port, Some(12345));
    assert_eq!(packets[0].dst_port, Some(80));
}

#[test]
fn pcap_http_response() {
    let packets = run_pcap(&fixtures().join("http_response.pcap"));
    assert_eq!(
        packets.len(),
        1,
        "http_response.pcap should contain 1 packet"
    );
    assert_eq!(packets[0].protocol, Protocol::Http);
    assert!(
        packets[0].summary.contains("200") || packets[0].summary.contains("OK"),
        "summary should mention the response status: {}",
        packets[0].summary
    );
}

#[test]
fn pcap_dns_query() {
    let packets = run_pcap(&fixtures().join("dns_query.pcap"));
    assert_eq!(packets.len(), 1, "dns_query.pcap should contain 1 packet");
    assert_eq!(packets[0].protocol, Protocol::Dns);
    assert!(
        packets[0].summary.contains("query") || packets[0].summary.to_lowercase().contains("dns"),
        "summary: {}",
        packets[0].summary
    );
}

#[test]
fn pcap_dns_response() {
    let packets = run_pcap(&fixtures().join("dns_response.pcap"));
    assert_eq!(
        packets.len(),
        1,
        "dns_response.pcap should contain 1 packet"
    );
    assert_eq!(packets[0].protocol, Protocol::Dns);
    let s = packets[0].summary.to_lowercase();
    assert!(
        s.contains("response") || s.contains("answer") || s.contains("reply"),
        "summary: {}",
        packets[0].summary
    );
}

#[test]
fn pcap_arp_request() {
    let packets = run_pcap(&fixtures().join("arp_request.pcap"));
    assert_eq!(packets.len(), 1, "arp_request.pcap should contain 1 packet");
    assert_eq!(packets[0].protocol, Protocol::Arp);
    assert!(
        packets[0].summary.contains("Request") || packets[0].summary.contains("Who has"),
        "summary: {}",
        packets[0].summary
    );
}

#[test]
fn pcap_tcp_syn() {
    let packets = run_pcap(&fixtures().join("tcp_syn.pcap"));
    assert_eq!(packets.len(), 1, "tcp_syn.pcap should contain 1 packet");
    assert_eq!(packets[0].protocol, Protocol::Tcp);
    let s = packets[0].summary.to_lowercase();
    assert!(
        s.contains("syn") || s.contains("tcp") || s.contains("handshake"),
        "summary: {}",
        packets[0].summary
    );
}

#[test]
fn pcap_tls_handshake() {
    let packets = run_pcap(&fixtures().join("tls_handshake.pcap"));
    assert_eq!(
        packets.len(),
        1,
        "tls_handshake.pcap should contain 1 packet"
    );
    assert_eq!(packets[0].protocol, Protocol::Tls);
    assert!(
        packets[0].summary.contains("Client Hello")
            || packets[0].summary.contains("client hello")
            || packets[0].summary.contains("TLS"),
        "summary: {}",
        packets[0].summary
    );
}

// ── Mixed protocol pcap ───────────────────────────────────────────────

#[test]
fn pcap_mixed_contains_multiple_protocols() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    assert!(
        packets.len() > 1,
        "mixed.pcap should contain multiple packets, got {}",
        packets.len()
    );

    let protos: std::collections::HashSet<Protocol> =
        packets.iter().map(|p| p.protocol.clone()).collect();
    assert!(
        protos.contains(&Protocol::Http)
            || protos.contains(&Protocol::Dns)
            || protos.contains(&Protocol::Tcp)
            || protos.contains(&Protocol::Arp)
            || protos.contains(&Protocol::Tls),
        "mixed.pcap should contain at least one known protocol among {:?}",
        protos
    );

    // Every packet should have a non-empty summary
    for (i, p) in packets.iter().enumerate() {
        assert!(
            !p.summary.is_empty(),
            "packet {i} in mixed.pcap has empty summary"
        );
        assert!(p.length > 0, "packet {i} in mixed.pcap has zero length");
    }
}

// ── Filter integration with real pcap ─────────────────────────────────

#[test]
fn filter_tcp_on_mixed_pcap() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    let filter = netscope_core::filter::Filter::parse("tcp").unwrap();

    let tcp_packets: Vec<&Packet> = packets.iter().filter(|p| filter.matches(p)).collect();
    assert!(
        !tcp_packets.is_empty(),
        "mixed.pcap should contain at least one TCP packet"
    );
    for p in &tcp_packets {
        assert!(
            matches!(p.protocol, Protocol::Tcp | Protocol::Http | Protocol::Tls),
            "TCP filter matched non-TCP protocol: {:?}",
            p.protocol
        );
    }
}

#[test]
fn filter_http_on_mixed_pcap() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    let filter = netscope_core::filter::Filter::parse("http").unwrap();

    let http_packets: Vec<&Packet> = packets.iter().filter(|p| filter.matches(p)).collect();
    // If there are HTTP packets, verify they're properly identified
    for p in &http_packets {
        assert_eq!(p.protocol, Protocol::Http);
    }
}

#[test]
fn filter_dns_on_mixed_pcap() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    let filter = netscope_core::filter::Filter::parse("dns").unwrap();

    let dns_packets: Vec<&Packet> = packets.iter().filter(|p| filter.matches(p)).collect();
    for p in &dns_packets {
        assert_eq!(p.protocol, Protocol::Dns);
    }
}

#[test]
fn filter_arp_on_mixed_pcap() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    let filter = netscope_core::filter::Filter::parse("arp").unwrap();

    let arp_packets: Vec<&Packet> = packets.iter().filter(|p| filter.matches(p)).collect();
    for p in &arp_packets {
        assert_eq!(p.protocol, Protocol::Arp);
    }
}

#[test]
fn filter_port_80_on_mixed_pcap() {
    let packets = run_pcap(&fixtures().join("mixed.pcap"));
    let filter = netscope_core::filter::Filter::parse("tcp.port == 80").unwrap();

    let port80: Vec<&Packet> = packets.iter().filter(|p| filter.matches(p)).collect();
    for p in &port80 {
        assert!(
            p.src_port == Some(80) || p.dst_port == Some(80),
            "port 80 filter matched packet with ports {:?}→{:?}",
            p.src_port,
            p.dst_port
        );
    }
}

// ── Edge cases ────────────────────────────────────────────────────────

#[test]
fn pcap_file_not_found_errors_gracefully() {
    let mut eng = CaptureEngine::new();
    let (tx, _rx) = crossbeam_channel::unbounded();
    let result = eng.start_offline("nonexistent_file.pcap", None, None, tx);
    assert!(result.is_err(), "opening a nonexistent file should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Failed to open pcap") || err.contains("nonexistent"),
        "error message should mention the failure: {err}"
    );
}

#[test]
fn empty_pcap_produces_no_packets() {
    // An empty pcap stream (header only, no packets)
    let mut eng = CaptureEngine::new();
    let (tx, rx) = crossbeam_channel::unbounded();
    let header = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    eng.start_read_stream(
        Box::new(std::io::Cursor::new(header)),
        "empty",
        &CaptureOptions::default(),
        tx,
    )
    .unwrap();
    let packets: Vec<Packet> = rx.iter().collect();
    assert_eq!(packets.len(), 0, "empty pcap should yield zero packets");
    eng.stop();
}

#[test]
fn autostop_packet_limit_mixed_pcap() {
    let path = fixtures().join("mixed.pcap");
    let packets = run_pcap_with_limit(&path, 2);
    assert!(
        packets.len() <= 2,
        "autostop at 2 packets should deliver at most 2, got {}",
        packets.len()
    );
}

#[test]
fn consecutive_reads_produce_same_results() {
    let path = fixtures().join("mixed.pcap");
    let a = run_pcap(&path);
    let b = run_pcap(&path);
    assert_eq!(
        a.len(),
        b.len(),
        "consecutive reads should yield same count"
    );
    for (i, (pa, pb)) in a.iter().zip(b.iter()).enumerate() {
        assert_eq!(pa.protocol, pb.protocol, "packet {i} protocol mismatch");
        assert_eq!(pa.length, pb.length, "packet {i} length mismatch");
    }
}
