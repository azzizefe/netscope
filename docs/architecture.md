# Architecture

netscope is a Rust workspace with **4 members**: `core` (shared engine), `tui` (terminal UI), `desktop/src-tauri` (Tauri desktop app), and `tools/gen-fixtures` (test pcap generator).

## Workspace Layout

```
netscope/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── core/                   # Capture engine, dissectors, models, stats
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── models.rs          # Packet, Protocol, ConnectionInfo
│   │       ├── capture.rs         # CaptureEngine (live/offline + savefile)
│   │       ├── stats.rs           # StatsEngine (counters, bandwidth, top N)
│   │       └── dissectors.rs      # Top-level dispatch + fuzz test
│   │           └── dissectors/    # Per-protocol dissectors
│   │               ├── ethernet.rs
│   │               ├── ip.rs
│   │               ├── tcp.rs
│   │               ├── udp.rs
│   │               ├── icmp.rs
│   │               ├── arp.rs
│   │               ├── dns.rs
│   │               ├── http.rs
│   │               └── tls.rs
│   └── tui/                    # Terminal UI (ratatui + crossterm)
│       └── src/
│           ├── main.rs             # CLI parser (clap) + dispatch
│           ├── app.rs              # App state, packet buffer, filter, views
│           ├── colors.rs           # Protocol color definitions
│           ├── headless.rs         # Plain text + JSON output formatters
│           └── views/
│               ├── mod.rs          # View enum (Packets/Dashboard/Connections/DnsLog)
│               ├── packets.rs      # Packet table + detail panel + hex dump
│               ├── dashboard.rs    # Stats, bandwidth, protocol bars, top talkers
│               ├── connections.rs  # Placeholder
│               └── dns_log.rs      # DNS query/response log
├── desktop/                     # Tauri desktop app
│   ├── frontend/                # HTML/CSS/JS (vanilla, no build step)
│   │   ├── index.html
│   │   ├── styles.css
│   │   └── app.js
│   └── src-tauri/
│       ├── Cargo.toml
│       ├── tauri.conf.json
│       ├── capabilities/default.json
│       ├── icons/               # Generated icon set (32x32 … 512x512, ico, icns)
│       └── src/lib.rs           # Tauri commands + packet forwarding
├── tools/
│   └── gen-fixtures/            # pcap generator (etherparse-based)
├── fixtures/                    # 8 sample .pcap files (HTTP, DNS, ARP, TLS, TCP)
├── docs/                        # Documentation
│   ├── architecture.md
│   ├── core.md
│   ├── dissectors.md
│   ├── setup.md
│   ├── tui.md
│   ├── desktop.md
│   └── social-preview.svg
├── .github/
│   ├── workflows/
│   │   ├── ci.yml               # Lint + test + build (3 OS matrix)
│   │   └── release.yml          # Tag-triggered release (TUI + desktop bundles)
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── README.md
```

## Data Flow (TUI)

```
pcap (live/offline)
    │
    ▼
CaptureEngine (threaded, AtomicBool stop)
    │  output to pcap::Savefile (optional -w flag)
    ▼
crossbeam_channel::Sender ──► Packet channel
    │
    ▼
dissectors::dissect()
    ├─ ethernet::dissect_ethernet()
    ├─ ip::dissect_ipv4/6()
    ├─ tcp::dissect_tcp() ──► http/tls by port
    ├─ udp::dissect_udp() ──► dns by port 53
    ├─ arp::dissect_arp()
    ├─ icmp::dissect_icmp()
    ├─ dns::dissect_dns()
    ├─ http::dissect_http()
    └─ tls::dissect_tls()
    │
    ▼
Packet { timestamp, addrs, ports, protocol, length, summary, data }
    │
    ├─► StatsEngine::record_packet() ──► StatsSnapshot
    │
    ▼
App::packets (VecDeque<Packet>, max 10_000)
    │  filtered by case-insensitive substring match
    ▼
ratatui Terminal (4 views, protocol colors, detail panel, hex dump)
```

## Data Flow (Desktop)

```
Tauri frontend (JS) ──invoke()──► Tauri backend (Rust)
    │                                   │
    │  list_interfaces()                │ pcap::Device::list()
    │  start_capture(iface, filter)     │ CaptureEngine::start_live()
    │  stop_capture()                   │ engine.stop()
    │  open_pcap(path)                  │ CaptureEngine::start_offline()
    │  save_pcap(path)                  │ writes pcap from buffer
    │                                   │
    │  ◄──event("packet", PacketInfo)───│ packet forwarding thread
    │  ◄──event("capture-finished", ())─│ (offline mode)
```

## Dissector Dispatch Chain

1. Raw bytes enter `dissectors::dissect()`
2. Ethernet header parsed via etherparse, EtherType determines:
   - `0x0800` → IPv4
   - `0x86DD` → IPv6
   - `0x0806` → ARP
3. IP next-header protocol number:
   - `6` → TCP (dispatches to HTTP on port 80, TLS on port 443)
   - `17` → UDP (dispatches to DNS on port 53)
   - `1` → ICMP
4. Every dissector returns `DissectedResult` with human-readable `summary`
5. **Never panics** — malformed packets produce a descriptive `Unknown` result

## CI/CD Pipeline

### CI (every push/PR)
- **lint** (Ubuntu): `cargo clippy -- -D warnings` + `cargo fmt --check`
- **test** (Ubuntu, macOS, Windows): `cargo build` + `cargo test` (core + TUI)
- Npcap SDK automatically downloaded on Windows for compilation

### Release (tag v*)
- **TUI binary** on all platforms (uploaded as artifact)
- **Desktop installer** via `cargo tauri build` (NSIS/DMG/DEB+AppImage)
- **GitHub Release** created with all artifacts + auto-generated release notes

## Key Design Decisions

- **Human-readable summaries** are the core differentiator vs Wireshark — every packet tells a story
- **Zero panics** in dissectors — malformed input always returns graceful fallback
- **Shared core** — TUI and Desktop use the exact same `netscope-core` crate
- **Event-driven desktop** — Tauri `emit("packet", ...)` for real-time streaming
- **TUI filter** — characters typed directly (no `/` prefix), matches summary/addr/protocol
- **Protocol colors** are consistent between TUI and Desktop frontend
