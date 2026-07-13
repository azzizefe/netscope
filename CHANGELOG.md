# Changelog

All notable changes to netscope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **TUI selection vs. display filter**: keyboard navigation (`↑/↓`, `j/k`),
  mouse-wheel scrolling and Follow Stream (`F`) now operate on the *filtered*
  packet list the screen shows. Previously they used the unfiltered buffer, so
  with an active filter the cursor could walk past the last visible row
  (blanking the detail/hex panes) and Follow Stream could open the wrong
  conversation. The detail tree and hex dump likewise resolve the selected row
  through the filter, and live capture keeps the same packet selected as old
  frames are evicted from the 10 000-packet ring.
- **Paused TUI capture no longer buffers unbounded packets**: while paused the
  capture channel is drained and discarded instead of growing without limit.
- **Restarting a desktop capture (or opening a file) clears stale state**: the
  packet buffer and learned DNS hostname cache are reset so the new session
  doesn't inherit rows or names from the previous one.

### Security

- Upgraded `maxminddb` 0.24 → 0.27 (RUSTSEC-2025-0132) and moved the GeoIP
  code to the new `lookup`/`decode` API.
- `cargo update`: `quick-xml` 0.39.4 → 0.41.0 (RUSTSEC-2026-0194/0195, via
  Tauri 2.11.5) — `cargo audit` now reports zero vulnerabilities.

### Changed

- **netscope now makes zero outbound network calls — fully offline, like
  Wireshark.** The opt-in `ipwho.is` online GeoIP lookup has been removed
  (frontend fetch, the settings toggle and its UI, and the `connect-src`
  allowance in the CSP, which is now `'self'` only). IP geolocation still works
  via a local, offline MaxMind `.mmdb` database — the only GeoIP path. The app
  captures and analyses entirely on the user's machine; there is no server, no
  telemetry, and nothing to phone home to.
- **Windows installer artifacts are no longer committed to the repository**
  (`dist/` is gitignored) — downloads come from GitHub Releases, built by the
  `release.yml` workflow on version tags.
- CI now also runs the desktop frontend vitest suite (72 tests) on every
  push/PR alongside the Rust jobs.

### Added

- **pcapng support in the memory-mapped reader** (`crates/core/src/stream.rs`).
  pcapng is Wireshark's *default* save format; until now the mmap fast path
  only handled classic `.pcap` and pcapng fell back to the slower streaming
  libpcap reader. `LazyCapture` now walks pcapng block structure (Section
  Header, Interface Description, Enhanced/Simple/legacy Packet Blocks) in
  either byte order, honours each interface's `if_tsresol` timestamp
  resolution (normalising to nanoseconds), and indexes ~24 bytes per packet
  with zero-copy payloads — so opening a large Wireshark capture gets the same
  no-up-front-load, parallel, virtually-scrolled treatment as `.pcap`. The
  desktop "Open" path picks this up automatically. 5 new tests.
- **JA3, JA4 and JA3S TLS fingerprinting** (`crates/core/src/dissectors/tls.rs`).
  Handshake dissection now parses the full ClientHello (ciphers, extensions,
  curves, ALPN, supported-versions, signature-algorithms) and ServerHello, and
  computes three fingerprints, all with RFC-8701 GREASE filtering:
  - **JA3** — MD5 over `version,ciphers,extensions,curves,point-formats`.
  - **JA4** (FoxIO) — the modern successor: `t{ver}{d/i}{#ciphers}{#exts}{alpn}`
    plus SHA-256 truncations of the sorted cipher list and of the sorted
    extensions (minus SNI/ALPN) with signature algorithms.
  - **JA3S** — MD5 over the ServerHello `version,cipher,extensions`, pairing
    with the client fingerprint for beacon/C2 detection.

  They surface in the TLS summary (`TLS ClientHello — github.com · JA4 … · JA3 …`,
  `TLS ServerHello · JA3S …`) so they are searchable, filterable, and matchable
  against threat-intel feeds even when the rest of the session is encrypted
  (ROADMAP §5.2) — something Wireshark needs a plugin for. Both hello parsers
  are fully bounds-checked (fuzzed over every truncation). 13 new tests.
- **Display-filter fields for the TLS fingerprints**: `tls.ja3` / `ja3`,
  `tls.ja4` / `ja4`, `tls.ja3s` / `ja3s`, recomputed from the handshake bytes
  on demand (no change to the packet model). So the TUI/core filter box now
  takes `ja3 == <hash>`, `ja4 contains "t13d"`, `ja3s == <hash>` alongside the
  existing fields. Documented in `docs/filters.md`, which now also covers the
  full Wireshark-style display-filter grammar the box already accepted.
- **TUI unit tests** for the app event loop: packet-ring eviction and
  selection tracking in `tick()`, pause-drain and channel-discard behaviour,
  display-filter fallback logic, key handling, headless output formatting
  (plain + JSON) and the Connections view formatters — 30 tests in
  `netscope-tui`, up from 14.

- **UI/UX polish across both frontends** (ROADMAP §6). **TUI (§6.1):** an
  expandable protocol detail tree (`crates/tui/src/detail.rs`, `Enter` focuses
  it, `←/→` collapse/expand) built from the frame bytes; Follow Stream
  (`stream.rs`, `F`) reconstructing a conversation as two-directional text; an
  Insights view (`insights.rs`) porting the desktop security/privacy findings;
  mouse support (crossterm capture — click rows/tabs, wheel scrolls) with a new
  clickable tab strip; a theme system (`theme.rs`, `T` to cycle or
  `$NETSCOPE_THEME`) with dark/light/solarized/dracula/monokai; and
  user-selectable packet-list columns (`columns.rs`, `C`). **Desktop (§6.2):**
  the filter box now signals syntax by colour (green = valid + hits, amber =
  valid/free-text, red = invalid); grammar-aware filter autocomplete
  (`NetscopeFilter.suggest` — fields → operators → values, keyboard + click); a
  large-capture load progress bar (determinate via a new `capture-total` IPC
  event, indeterminate otherwise); a View ▸ Columns… chooser (show/hide +
  ▲▼ reorder, persisted); and right-click tab pinning. **Accessibility (§6.3):**
  ARIA landmarks/roles (`banner`, `tablist`/`tab`, `contentinfo`), an
  `aria-live` capture-status region, arrow-key tab navigation and a visible
  `:focus-visible` ring, a WCAG-AA high-contrast theme, interface/text scaling
  (90–130 %), an Okabe–Ito colour-blind-safe protocol palette, and
  `prefers-reduced-motion` support. **Data viz (§6.4):** four new dashboard
  cards — TCP handshake round-trip-time scatter, TCP window-size-over-time
  (zero-windows flagged), a host↔host byte-intensity heatmap, and a flow-graph
  ladder for the busiest conversation. TUI: 14 new unit tests; desktop: 5 new
  filter-suggest tests (72 frontend tests green).

- **GPU-accelerated visualisation** (desktop, ROADMAP §4.3) — the Topology map
  switches to a WebGL renderer above 150 hosts: edges as GL lines, hosts as
  round point sprites, busiest-host labels overlaid as HTML. The cap rises
  from 60 (SVG) to the 1500 busiest hosts, and the force layout swaps its
  all-pairs repulsion for a spatial grid on big graphs (~O(n·k) per iteration
  — 1500 hosts lay out and draw in ~130 ms). Small graphs keep the SVG path
  with labels, tooltips and hover intact; no WebGL means a clean fallback.
  New **I/O Graph** dashboard card: every packet drawn as a GPU point
  (time × size, log scale; RST/malformed in red) under a bucketed
  packets-per-second line — point data streams into a growing GPU buffer, so
  a million-packet capture redraws with two draw calls.

- **Benchmark & profiling infrastructure** (`crates/core/benches/`, ROADMAP
  §4.4) — three criterion/allocator benchmarks run in CI on every push:
  `parse_throughput` (mixed-traffic `dissect()`, ~3.1 M pkt/s), `filter_match`
  (100k display-filter evaluations, ~32 M evals/s, plus per-filter costs) and
  `mem_usage` (a counting global allocator measures the real heap of 1M
  dissected packets — ~269 MiB — and proves cloned packets share frame bytes).
  Flamegraph instructions in `docs/core.md`.


- **22 new protocol dissectors — databases, OT, VoIP media, security/VPN, IoT,
  operator/routing** (ROADMAP §3.3–3.8). Each is wired end to end: well-known
  port (or EtherType / IP-protocol) dispatch, its own `Protocol` variant with a
  display name and colour in both UIs, flow grouping and ranking, a
  beginner-friendly Learn-mode lesson, and unit + end-to-end dispatch tests.
  - **Databases** (`§3.4`): PostgreSQL (`postgres.rs`, TCP 5432 — startup/SSL,
    Simple Query SQL, ErrorResponse), MySQL/MariaDB (`mysql.rs`, 3306 —
    handshake, COM_QUERY, ERR), MongoDB (`mongodb.rs`, 27017 — OP_MSG/OP_QUERY
    command & collection), Redis (`redis.rs`, 6379 — RESP array/inline commands
    & replies), Cassandra (`cassandra.rs`, 9042 — CQL frames + QUERY text).
    Filter aliases `postgres`/`psql`/`pgsql`/`mongo`.
  - **Industrial / OT** (`§3.5`): Modbus/TCP (`modbus.rs`, 502 — function codes
    + exceptions), DNP3 (`dnp3.rs`, 20000 — link function + addresses), BACnet/IP
    (`bacnet.rs`, UDP 47808 — Who-Is/I-Am/ReadProperty), EtherNet/IP
    (`enip.rs`, 44818 — encapsulation commands + session), OPC UA (`opcua.rs`,
    4840 — HEL/ACK/OPN/MSG).
  - **Media / VoIP** (`§3.6`): RTP + RTCP (`rtp.rs`) — structural heuristic on
    dynamically negotiated UDP ports (version + payload-type sanity), payload
    type/codec, sequence, SSRC; RTCP SR/RR/SDES/BYE/APP.
  - **Security / VPN** (`§3.7`): Kerberos (`kerberos.rs`, TCP/UDP 88 —
    AS/TGS/AP-REQ/REP, TCP & UDP framing), LDAP (`ldap.rs`, 389 — BER parse,
    bindRequest DN, searchRequest), RADIUS (`radius.rs`, UDP 1812/1813 — codes +
    id), OpenVPN (`openvpn.rs`, 1194 — opcode/key, UDP+TCP), WireGuard
    (`wireguard.rs`, UDP 51820 — handshake/transport), IPsec ESP/AH
    (`ipsec.rs`, IP proto 50/51 — SPI + sequence tracking).
  - **IoT** (`§3.8`): MQTT (`mqtt.rs`, TCP 1883 — CONNECT client-id, PUBLISH
    topic, all message types), CoAP (`coap.rs`, UDP 5683 — type/code + Uri-Path
    reconstruction). BLE/Zigbee/CAN deferred (need a non-Ethernet capture path).
  - **Operator / routing** (`§3.3`): BGP (`bgp.rs`, TCP 179 — OPEN/UPDATE/
    NOTIFICATION/KEEPALIVE + AS), full OSPF (`ospf.rs`, IP proto 89 —
    Hello/DD/LSR/LSU/LSAck + router/area), LLDP (`lldp.rs`, EtherType 0x88CC —
    system name/port from TLVs), LACP/slow protocols (`lacp.rs`, 0x8809),
    STP/RSTP/MSTP (`stp.rs`, 802.3 LLC BPDU + root bridge), MPLS (`mpls.rs`,
    0x8847/0x8848 — unwraps the label stack and dissects the inner IP packet).

- **Parallel capture pipeline** (`crates/core/src/pipeline.rs`, ROADMAP §2.1) —
  dissection moved off the capture thread: raw frames now flow through a
  lock-free ring buffer (`crossbeam` `ArrayQueue`) into a rayon-backed
  dissector stage that parses batches across all cores while preserving
  arrival order. Live capture never blocks the wire loop — a full ring drops
  the frame and counts it; file reads apply backpressure instead so nothing
  is lost. New `CaptureEngine::pipeline_stats()` (and a `get_capture_stats`
  Tauri command) expose received / dropped / dissected counters. An optional
  `async` cargo feature adds `AsyncCaptureEngine`, a tokio-channel facade for
  the planned headless/REST server mode. 5 new unit tests, including an
  order-preservation test and a full-pipeline throughput floor.

- **Lazy pcap reader — mmap + packet index + LRU** (`crates/core/src/stream.rs`,
  ROADMAP §2.2) — `LazyCapture` memory-maps classic pcaps, indexes only the
  16-byte record headers (~24 bytes per packet instead of a parsed `Packet`),
  and dissects on first access with a bounded LRU cache; `packets_range()`
  dissects cold pages in parallel with rayon and `find_by_time()` binary
  searches the timestamp index. Both endiannesses and µs/ns resolutions are
  handled; truncated tails are tolerated; pcapng falls back to the streaming
  libpcap reader. The desktop's *Open pcap* now uses it and emits packets in
  `packets-batch` IPC events (~1000× fewer events on big files). 9 new unit
  tests.

- **Declarative protocol plugins** (`crates/core/src/plugins.rs`, ROADMAP §2.3) —
  recognise new protocols without touching Rust: drop a TOML file into
  `~/.netscope/plugins/` naming the protocol, its transport and ports, plus
  optional payload heuristics (`prefix`, `prefix_hex`, `contains`) and a
  summary template. Plugins run after every built-in dissector and before the
  generic TCP/UDP fallback, so they can claim unknown traffic but never shadow
  a built-in. Matches surface as their own protocol everywhere — packet list,
  colours, flows, Learn mode, display filters (`redis` matches a plugin named
  "Redis") — in both UIs. Desktop gains `list_plugins` / `reload_plugins`
  commands; the TUI loads plugins at startup. 9 new unit tests.

- **Layered configuration** (`crates/core/src/config.rs`, ROADMAP §2.4) — one
  discoverable home for user settings, shared by TUI and desktop:
  `~/.netscope/` (override with `$NETSCOPE_CONFIG_DIR`) holding `config.toml`,
  `profiles/*.toml` (partial overlays deep-merged over the global file;
  selected via `$NETSCOPE_PROFILE` or `general.profile`), `coloring-rules.toml`
  (new `[[rule]]` TOML form *and* the legacy line form both parse — the TUI
  reads this location before the legacy per-OS path), `plugins/` and
  `geoip.mmdb` — which the desktop now auto-loads at startup, no clicking
  through the Profile menu needed. Loading never fails: broken or missing
  files yield defaults. New `get_app_config` Tauri command surfaces the loaded
  config to the frontend. 13 new unit tests.

- **Virtual scrolling in the desktop packet list** (ROADMAP §2.2) — the list
  now renders only the rows inside the viewport (plus overscan) over a
  full-height spacer, replacing the old "last 500 rows" cap: every captured
  packet is reachable by scrolling, and a 100k-row capture scrolls as smoothly
  as a 100-row one. Live captures still follow the tail until you scroll up.
  4 new vitest cases.

- **HTTP/2 + gRPC dissection** (`crates/core/src/dissectors/http2.rs`) —
  cleartext HTTP/2 (h2c) on any TCP port, recognised by the client connection
  preface or a strictly-validated frame chain (per-type flag/length/stream-id
  rules, reserved bits): SETTINGS, HEADERS, DATA, PING, GOAWAY (with error
  names), WINDOW_UPDATE and friends. gRPC calls riding on those frames are
  labelled as their own protocol, spotted by `content-type: application/grpc`
  in a HEADERS block (matched raw *and* in its HPACK-Huffman byte form — no
  Huffman decoder needed, a fixed string encodes to fixed bytes) or by DATA
  frames carrying exact gRPC length-prefixed messages. HTTP/1.1 `Upgrade: h2c`
  handshakes get a summary note like WebSocket upgrades. New `http2` / `grpc`
  display-filter predicates (Rust + JS), colours, Learn lessons and per-packet
  explanations in both UIs. 16 new unit tests.

- **User-defined coloring rules in the TUI** (`crates/tui/src/colors.rs`) —
  the terminal UI now matches the desktop's View > Coloring rules: rules load
  from `~/.config/netscope/colors` (or `%APPDATA%\netscope\colors`, or
  `--colors <file>`), one `<hex-color> <display filter>` per line, checked
  top-down — the first match tints the packet row, everything else keeps its
  protocol colour. Ships the same defaults as the desktop (bad TCP red, HTTP
  errors orange, handshakes grey…) when no file exists. 4 new unit tests.

- **Offline GeoIP database** (desktop) — the Profile menu can now load a
  MaxMind `.mmdb` file (e.g. the free GeoLite2-City/Country/ASN): IP locations
  then resolve locally via a new `geoip_lookup` Tauri command — private, no
  network calls, works offline, and takes precedence over the opt-in ipwho.is
  web lookup. The database path persists and reloads on start; localised UI in
  all 7 languages (Turkish also gained the previously-missing GeoIP strings).

- **Byte-field highlighting** (desktop) — clicking a field in the packet-detail
  tree (MAC addresses, EtherType, IP source/destination, TCP/UDP ports)
  highlights exactly its bytes in the hex view, Wireshark-style. A new
  `fieldRanges()` helper locates each field in the raw frame (walking VLAN tags
  and the IPv4 IHL / IPv6 header); the hex dump now renders per-byte spans. A
  dedicated **Ethernet II** layer with clickable MACs was added to the tree.
  Unit-tested (6 vitest cases).

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

- **Capture-driver detection** (desktop) — a clickable `⚠ Npcap?` badge with
  per-OS setup help and a copyable npcap.com link when no interfaces are found.

- **Monitor-mode (rfmon) capture** — opt-in raw 802.11 capture: `--monitor`
  on the TUI and a Wireless-menu toggle in the desktop, threaded through
  `start_live`. Enabled on Linux/macOS with a monitor-capable adapter; on
  Windows it fails with a clear message (the `pcap` crate doesn't expose rfmon
  there) — monitor-mode `.pcap` files still load and dissect on all platforms.

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

### Changed

- **SIMD-accelerated parsing hot paths** (ROADMAP §4.1) — byte scans now use
  the `memchr` crate (SSE2/AVX2/NEON): first-line extraction shared by the
  line-oriented dissectors, plugin `contains` payload matching (previously an
  O(n·m) `windows()` scan), and C-string scans in the PostgreSQL / MySQL /
  MongoDB dissectors. The HTTP dissector no longer UTF-8-validates entire
  payloads — it decodes only the ~2 KiB header block, so responses with
  binary bodies (images, gzip) now parse their status line instead of
  reporting "non-UTF8 payload"; the TCP upgrade-handshake probe applies the
  same cap. Also fixes a latent panic when a 2048-byte header slice landed
  mid-way through a multi-byte UTF-8 character.

- **Memory footprint** (ROADMAP §4.2) — `Packet.data` is now `bytes::Bytes`:
  cloning a packet (flow tracking, the lazy-reader LRU cache, UI copies)
  bumps a refcount instead of reallocating the frame. Hostnames learned by
  passive DNS are interned (`Arc<str>`), so a CDN name resolving to dozens of
  IPs costs one allocation. Display-filter evaluation dropped its per-packet
  allocations (borrowed HTTP heads, allocation-free case-insensitive
  equality). IP addresses were already `std::net::IpAddr`.

- **`CaptureEngine` internals** — both `start_live` and `start_offline` now
  route through the parallel pipeline (ROADMAP §2.1); public signatures are
  unchanged. `stop()` drains the dissector stage before returning, so the
  last packets of a capture are never lost.
- One `unsafe` block entered the workspace (the `memmap2::Mmap::map` call in
  `stream.rs`, with a documented safety contract) — the previous
  zero-`unsafe` note in AUDIT.md is updated accordingly.

### Fixed

- **TUI Learn view now shows every lesson** — it was zipping the lesson list
  against a stale 8-protocol colour table, silently truncating the other
  lessons. `education::all_lessons()` now returns `(Protocol, Lesson)` pairs,
  so new lessons appear automatically with their protocol colour. WebSocket
  and VXLAN lessons were also added to the Learn views of both UIs.

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
