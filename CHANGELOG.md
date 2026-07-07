# Changelog

All notable changes to netscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Wireshark-style menu bar** (desktop) — a menu bar above the view tabs with
  File / Edit / View / Analyze / Statistics / Telephony / Wireless / Tools, all
  items wired to real actions (localised, EN + TR):
  - **File** — Open / Save capture (native file dialog), Export report, and
    **Export packets as CSV / JSON**
  - **Edit** — Find packet, Clear filter, Preferences
  - **View** — jump to any view; time & display settings
  - **Analyze** — apply selected packet as a filter, Follow stream, Expert
    info, display-filter reference
  - **Statistics** — **Protocol Hierarchy** and **Endpoints** tables,
    Conversations, I/O graph
  - **Telephony** — **VoIP calls** (SIP call log)
  - **Wireless** — **WLAN traffic** (SSIDs seen) and a monitor-mode toggle
  - **Tools** — **Firewall ACL rules** (netsh + iptables), **Credentials**
    (cleartext-exposure list), Blocked IPs
  - New pure compute helpers are unit-tested (9 vitest cases)

- **802.11 (Wi-Fi) dissection** (`crates/core/src/dissectors/`)
  - Link-layer-aware capture: the dissector now branches on the pcap
    data-link type, so captures on Wi-Fi (`DLT_IEEE802_11` and radiotap
    `DLT_IEEE802_11_RADIO`) are decoded as 802.11 instead of Ethernet
  - `radiotap.rs` — parses the monitor-mode radiotap header (length, signal
    dBm, channel MHz)
  - `wlan.rs` — 802.11 management/control/data frames, with SSID extraction
    from beacons and probes (hidden SSIDs flagged) and BSSID display
  - New first-class `802.11` protocol with colour, Learn lesson and
    `wlan` / `wifi` / `802.11` display-filter predicates
  - 11 new unit tests

- **Display-filter language** (`crates/core/src/filter.rs`) — a Wireshark-style
  filter grammar shared by the TUI and desktop:
  - Fields: `ip.addr` / `ip.src` / `ip.dst`, `port` / `tcp.port` / `udp.port`,
    `frame.len` (aliases `len`, `length`)
  - Comparisons `== != > < >= <=` and `contains`; boolean `&&` `||` `!`
    (and `and` / `or` / `not`) with parentheses
  - Bare protocol predicates (`tcp`, `udp`, `dns`, `http`, `tls`, `dhcp`,
    `ntp`, `mdns`, `snmp`, `quic`, `sip`, `ip`/`ipv4`/`ipv6`)
  - Invalid expressions fall back to the existing substring search, so
    free-text typing still works; wired into both the TUI filter box and the
    desktop packet list, with a mirrored JS implementation and vitest coverage
  - 23 Rust + 15 JS unit tests

- **Deeper protocol dissection** (`crates/core`)
  - VLAN 802.1Q and QinQ (802.1ad) tag unwrapping — tagged frames now reach
    their inner IP/ARP dissector, with the VLAN id shown in the summary
  - New UDP application-layer dissectors, each a first-class protocol with its
    own colouring, flow labelling and Learn-tab lesson:
    - **DHCP / BOOTP** (67/68) — message type (Discover/Offer/Request/ACK/…)
      and the assigned address
    - **NTP** (123) — version, mode (client/server/…), stratum
    - **mDNS** (5353) — local service discovery, parsed via the DNS format
    - **SNMP** (161/162) — version and (for v1/v2c) the plaintext community
    - **QUIC** (443/80) — long/short header detection with handshake phase
    - **SIP** (5060/5061) — VoIP request method / status line
  - New TCP application-layer dissectors, likewise first-class:
    - **SSH** (22) — version banner, then encrypted
    - **FTP** (21) — commands / replies (`PASS` masked)
    - **SMTP** (25/587) — commands / replies (`AUTH` masked)
    - **IMAP** (143) — tagged commands (`LOGIN` masked)
    - **POP3** (110) — commands / replies (`PASS` masked)
    - **Telnet** (23) — option negotiation vs. cleartext terminal text
    - **RDP** (3389) — Remote Desktop, with connection-request detection
  - 35 new unit tests covering the added dissectors

## [0.1.0] — 2026-07-07

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

- **Desktop app** (`desktop/`, Tauri 2)
  - Native window with ten views: Packets, Connections, Dashboard, Topology,
    DNS Log, Insights, Privacy, Diff, Script, Learn
  - Wireshark-style three-pane inspector: protocol tree, hex/ASCII view,
    plain-language "what is this?" per packet
  - Follow Stream, Expert Info badges, payload beautifier (JSON/XML),
    protocol guesser, hex → C/Rust/Python literals
  - 🛡 Insights security & privacy scan (cleartext secrets, port scans,
    signature matches, exfiltration, beaconing, encryption ratio)
  - 🔎 Privacy X-ray: per-site trackers, cookies, data cost
  - Traffic diff, live "Grafana-style" dashboard with sparklines and
    bandwidth projection, force-directed topology map
  - JavaScript script console over the captured packet stream
  - Profiles, workspace modes, noise filter, themes, shareable Markdown
    report with secret scrubbing and IP anonymisation
  - Replay (repeater) for resending a payload to a host/port
  - 7-language UI (EN, DE, FR, IT, PT, AR, TR)
  - Opt-in GeoIP lookup (off by default — no external calls unless enabled)
  - Connections tab blocks a remote host with one click
    (`block_ip`/`unblock_ip`/`list_blocked`/`is_elevated` commands);
    Windows build embeds a `requireAdministrator` manifest so blocking works
  - Runs straight from source: `cargo run -p netscope-desktop`

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
