# Changelog

All notable changes to netscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — Unreleased

### Added

- **Core Engine** (`crates/core`)
  - Packet capture via `pcap` crate (live + offline)
  - BPF filter support
  - Protocol dissectors: Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, TLS
  - Human-readable summaries (DNS domains, TLS SNI, HTTP paths, TCP handshake states)
  - Real-time stats engine (bandwidth, top talkers, protocol distribution, DNS domains)

- **Terminal UI** (`crates/tui`)
  - Four-view layout: Packets, Dashboard, Connections, DNS Log
  - Protocol-colored row highlighting
  - Packet detail panel with expandable layers
  - Togglable hex dump
  - Real-time dashboard with bandwidth graph and protocol distribution
  - DNS-specific filtered log view
  - Smart filter (free text matching on summary/protocol/address)
  - Help overlay
  - Tab-based view switching

- **CLI**
  - Interactive TUI mode (auto-interface or `-i`)
  - Offline pcap analysis (`-r`)
  - Capture saving (`-w`)
  - BPF filter (`-f`)
  - Interface listing (`-D`)
  - Headless plain text output (`--headless`)
  - JSON Lines output (`--json`)

- **Documentation**
  - Architecture guide (`docs/architecture.md`)
  - Core API reference (`docs/core.md`)
  - Dissector guide (`docs/dissectors.md`)
  - Setup guide (`docs/setup.md`)

### Quality

- 58 unit tests across all modules
- Sample `.pcap` fixtures for offline testing
- Fuzz test (1000 random garbage packets, zero panics)
- Performance benchmark (10k packets at >2M pkt/s throughput)
- `cargo clippy -- -D warnings` clean
- `cargo fmt --check` clean

### Notes

- Windows builds require Npcap (WinPcap-compatible mode)
- Linux requires `CAP_NET_RAW` capability or root for live capture
- Desktop app (Tauri) coming in a future release
