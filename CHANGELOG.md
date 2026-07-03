# Changelog

All notable changes to netscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — Unreleased

### Added

- **Core Engine** (`crates/core`)
  - Packet capture via `pcap` crate (live + offline)
  - BPF filter support
  - Protocol dissectors: Ethernet, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, DNS, HTTP, TLS
  - Human-readable summaries (DNS domains, TLS SNI, HTTP paths, TCP handshake
    states, ICMP ping/TTL/neighbor-discovery types, IGMP/GRE/ESP/OSPF names)
  - **Passive hostname resolution** (`names.rs`) — learns IP → domain from
    captured DNS responses; UI shows `github.com:443` instead of bare IPs
  - **Traffic blocking** (`firewall.rs`) — block a remote host via OS firewall
    rules (`netsh advfirewall` on Windows, named `netscope-block-<ip>`).
    Locale-independent rule lookup, elevation-aware, fully reversible.
  - **Education content** (`education.rs`) — beginner-friendly per-protocol
    lessons, a glossary, and context-aware one-line packet explanations.
  - **Smart default interface selection** — scores devices by connection
    status and routable IPv4; skips loopback and virtual adapters
  - Real-time stats engine (bandwidth, top talkers, protocol distribution, DNS domains)
  - IPv6 endpoints rendered in standard bracket form: `[2001:db8::1]:443`

- **Terminal UI** (`crates/tui`)
  - Four-view layout: Packets, Dashboard, Connections, DNS Log
  - Protocol-colored row highlighting
  - Packet detail panel with expandable layers
  - Togglable hex dump
  - Real-time dashboard with bandwidth graph and protocol distribution
  - DNS-specific filtered log view
  - Smart filter (free text matching on summary/protocol/address/hostname)
  - Interactive Connections view — select a flow and block/unblock its remote
    host with `b`/`u`; blocked flows render red with a `⛔` mark and count
  - **Learn view** — scrollable plain-language protocol guide + glossary for
    people new to networking; detail panel shows an `ℹ` explanation per packet
  - Status bar shows the friendly adapter name ("Intel(R) Wi-Fi 6 AX201"),
    not the raw `\Device\NPF_{...}` identifier; warns when not elevated
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
  - Firewall inspection/cleanup (`--list-blocked`, `--unblock-all`)

- **Documentation**
  - Documentation index (`docs/README.md`)
  - Architecture guide (`docs/architecture.md`)
  - Core API reference (`docs/core.md`)
  - Dissector guide (`docs/dissectors.md`)
  - Setup guide (`docs/setup.md`)
  - BPF filter cookbook (`docs/filters.md`)
  - FAQ & troubleshooting (`docs/faq.md`)
  - Turkish user guide (`docs/KULLANIM.md`)

### Quality

- 88 unit tests across all modules
- Sample `.pcap` fixtures for offline testing
- Fuzz test (1000 random garbage packets, zero panics)
- Performance benchmark (10k packets at >2M pkt/s throughput)
- `cargo clippy -- -D warnings` clean
- `cargo fmt --check` clean

### Notes

- Windows builds require Npcap (WinPcap-compatible mode)
- Linux requires `CAP_NET_RAW` capability or root for live capture
- Desktop app (Tauri) coming in a future release
