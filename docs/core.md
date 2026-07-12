# Core Crate Reference

The `netscope-core` crate provides shared types, capture engine, dissectors, and real-time stats. Zero UI dependencies.

## Models (`models.rs`)

### `Protocol` enum
```rust
pub enum Protocol {
    Tcp, Udp, Dns, Http, Tls, Icmp, Arp,
    Unknown(String),
}
```
Implements `Display` + `Clone` + `PartialEq` + `Eq` + `Hash`.

### `Packet` struct
```rust
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub length: usize,
    pub summary: String,      // Human-readable one-liner
    pub data: Vec<u8>,         // Raw packet bytes
}
```
Implements `Clone`.

### `ConnectionInfo` struct
Groups related packets into a flow.
```rust
pub struct ConnectionInfo {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub packets: Vec<Packet>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}
```
Methods: `duration()` (elapsed wall clock), `byte_count()` (total bytes).

---

## Capture Engine (`capture.rs`)

### `list_interfaces() -> Result<Vec<pcap::Device>>`
Lists network interfaces. Platform-specific error messages (Npcap on Windows, sudo on Unix).

### `default_interface() -> Result<pcap::Device>`
Zero-config interface pick. Scores every device — connected status, up/running
flags, presence of a routable IPv4 address — and penalizes loopback and
virtual adapters (WAN Miniport, Hyper-V, Wi-Fi Direct). This is what makes
`netscope-tui` with no arguments land on your real Wi-Fi/Ethernet instead of
the first virtual adapter in the list.

### `friendly_name(dev: &pcap::Device) -> String` / `friendly_name_of(raw_name: &str) -> String`
Human-readable device label: the description (`"Intel(R) Wi-Fi 6 AX201"`)
when available, the raw name (`\Device\NPF_{...}`) otherwise.

### `CaptureEngine`
Manages a background capture thread with `AtomicBool` stop flag. Since the
ROADMAP §2.1 rework, dissection no longer happens on the capture thread: raw
frames flow through the parallel pipeline (below), and the `Sender<Packet>`
receives finished packets in arrival order.

```rust
impl Default for CaptureEngine  // new()
pub fn new() -> Self
pub fn start_live(
    &mut self,
    interface: &str,
    bpf_filter: Option<&str>,
    output_path: Option<&str>,     // simultaneous savefile
    packet_tx: Sender<Packet>,
    monitor: bool,                 // rfmon / raw 802.11
) -> Result<()>
pub fn start_offline(
    &mut self,
    filepath: &str,
    bpf_filter: Option<&str>,
    output_path: Option<&str>,
    packet_tx: Sender<Packet>,
) -> Result<()>
pub fn stop(&mut self)
pub fn is_running(&self) -> bool
pub fn pipeline_stats(&self) -> Option<pipeline::StatsSnapshot>  // received/dropped/dissected
```

Key details:
- Live: promiscuous mode, snaplen 65535, 1-second timeout
- BPF filter compiles before capture starts; returns descriptive error on invalid filter
- `output_path` creates a `pcap::Savefile` — packets are written as they arrive
- Savefile errors are logged to stderr (not silently swallowed)
- Threads are named `"capture"` / `"dissect"` for debugging
- Drop calls `stop()` automatically; `stop()` drains the pipeline so no packet is lost

### `AsyncCaptureEngine` (feature = `async`)
Tokio-friendly facade for async consumers (the planned REST/WebSocket server
mode). Same capture internals; packets arrive on a bounded
`tokio::sync::mpsc::Receiver<Packet>` fed by a bridge thread.

```rust
// Cargo.toml: netscope-core = { version = "...", features = ["async"] }
let (mut engine, mut rx) = AsyncCaptureEngine::start_offline("file.pcap", None, 1024)?;
while let Some(pkt) = rx.recv().await { /* … */ }
```

---

## Parallel Pipeline (`pipeline.rs`) — ROADMAP §2.1

```text
Capture thread ──▶ lock-free ring (crossbeam ArrayQueue) ──▶ rayon dissector pool ──▶ Sender<Packet>
```

- **`Pipeline::start(linktype, tx, running)`** spawns the dissector stage; it
  drains the ring in batches of ≤512 and parses batches ≥32 frames with
  `rayon` across all cores, preserving arrival order.
- **`Producer::push_live`** never blocks: a full ring drops the frame and
  counts it (`StatsSnapshot::dropped`) — the wire loop is never stalled.
- **`Producer::push_blocking`** applies backpressure instead — used for file
  reads where dropping would corrupt analysis.
- **`Pipeline::stats()`** → `StatsSnapshot { received, dropped, dissected }`.
- If the downstream receiver disconnects, the pipeline stores `false` into the
  shared `running` flag so the capture loop winds down too.

---

## Lazy pcap Reader (`stream.rs`) — ROADMAP §2.2

`LazyCapture` memory-maps a classic pcap (`memmap2`), scans only the 16-byte
record headers into an index (~24 bytes/packet), and dissects packets on
first access with a bounded LRU cache (4096 entries):

```rust
let cap = LazyCapture::open("big.pcap")?;
cap.len();                       // packet count, no parsing done yet
cap.raw(i);                      // zero-copy &[u8] into the map
cap.packet(i);                   // dissect on demand, LRU-cached
cap.packets_range(start, n);     // page for UI viewports, rayon-parallel
cap.find_by_time(ts);            // binary search over timestamps
```

Handles both endiannesses and µs/ns timestamp resolutions; truncated final
records are dropped like other readers do. pcapng is rejected with a clear
error — callers fall back to the streaming `CaptureEngine` (libpcap handles
pcapng), which is exactly what the desktop's *Open pcap* does.

---

## Protocol Plugins (`plugins.rs`) — ROADMAP §2.3

Declarative dissector plugins: drop a TOML file into `~/.netscope/plugins/`
and the protocol shows up in both UIs without recompiling.

```toml
# ~/.netscope/plugins/redis.toml
name = "Redis"
transport = "tcp"          # or "udp"
ports = [6379]
description = "Redis key-value store wire protocol (RESP)."

[match]                    # optional payload heuristics — all must hold
prefix = "*"               # payload starts with (text)
# prefix_hex = "2a31"      # …or hex bytes (wins over prefix)
# contains = "PING"        # payload contains

[display]
summary = "Redis — {first_line}"  # {name} {len} {src_port} {dst_port} {first_line}
```

- Plugins run **after** every built-in dissector and **before** the generic
  `TCP/UDP — N bytes` fallback: they can claim unknown traffic, never shadow
  a built-in protocol.
- Matches become `Protocol::Plugin { name, transport }` — coloring, flows,
  Learn mode and display filters (`redis` matches a plugin named "Redis")
  work like for built-ins.
- API: `plugins::load_dir(dir) -> LoadOutcome { loaded, errors }`,
  `plugins::load_from_config(&Config)`, `plugins::installed()`,
  `plugins::install(vec)` (registry is process-global; empty = disabled, and
  the dissector hook is a single atomic load when no plugins are installed).

---

## Layered Configuration (`config.rs`) — ROADMAP §2.4

One discoverable home for user settings, shared by TUI and desktop:

```text
~/.netscope/                  # or $NETSCOPE_CONFIG_DIR
├── config.toml               # global settings
├── profiles/<name>.toml      # partial overlays; only differences needed
├── coloring-rules.toml       # user coloring rules (TOML or legacy line form)
├── plugins/*.toml            # protocol plugins (above)
└── geoip.mmdb                # offline GeoIP DB (auto-loaded by the desktop)
```

- `Config::load()` never fails: missing/broken files yield defaults.
- Profiles deep-merge over `config.toml`; select one via `$NETSCOPE_PROFILE`,
  the `general.profile` key, or `Config::load_profile(dir, name)`.
- Path helpers resolve relative entries against the config dir:
  `geoip_database_path()`, `coloring_rules_path()`, `plugins_dir()`.
- `parse_coloring_rules(text)` reads both the `[[rule]]` TOML form and the
  legacy `RRGGBB <filter>` line form (used by the TUI).

---

## Dissectors (`dissectors.rs` + `dissectors/`)

### `DissectedResult`
```rust
pub struct DissectedResult {
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub summary: String,
}
```

### `dissect(data: &[u8]) -> DissectedResult`
Entry point — raw bytes → structured + human-readable result.

### Dissector Table

| Module | Input | Summary Examples |
|--------|-------|------------------|
| `ethernet` | raw bytes | (internal dispatch) |
| `ip` | Ethernet payload | (internal dispatch) |
| `tcp` | IP payload | `"TCP Connection opened (3-way handshake)"`, `"TCP SYN-ACK"`, `"TCP Connection closing (FIN)"`, `"TCP Connection reset (RST)"`, `"TCP — N bytes of payload"` |
| `udp` | IP payload | `"UDP — N bytes of payload"` (port 53 → DNS dispatch) |
| `icmp` | IP addrs + payload | `"Ping request (echo request)"`, `"Time-to-live exceeded"`, `"Neighbor solicitation (who has this IPv6?)"` |
| `arp` | Ethernet payload | `"ARP Request — Who has 192.168.1.1? Tell 192.168.1.2 (aa:bb:cc:dd:ee:ff)"`, `"ARP Reply — 192.168.1.1 is at aa:bb:cc:dd:ee:ff"` |
| `dns` | UDP port 53 | `"DNS Query — google.com"`, `"DNS Response — google.com → 142.250.74.46"`, `"DNS Response — example.com (no answers)"` |
| `http` | TCP port 80 | `"HTTP GET /api/users (HTTP/1.1)"`, `"HTTP POST /login (HTTP/1.1)"`, `"HTTP 200 OK (1234 bytes)"` |
| `tls` | TCP port 443 | `"TLS — github.com (HTTPS)"` (SNI), `"TLS Handshake (no SNI)"`, `"TLS — N bytes of encrypted data"` |

### Error handling
Every dissector returns gracefully on malformed input — no panics. Fuzz test validates 1000 random garbage packets produce zero panics.

---

## Hostname Cache (`names.rs`)

Passive DNS resolution — the feature behind `google.com → 142.250.74.46`.

### `NameCache`
```rust
pub fn new() -> Self
pub fn observe(&mut self, pkt: &Packet)                       // learn from DNS responses
pub fn name_for(&self, ip: IpAddr) -> Option<&str>            // lookup
pub fn display(&self, ip: IpAddr) -> String                   // hostname or IP
pub fn display_endpoint(&self, ip: IpAddr, port: Option<u16>) -> String  // "github.com:443"
```

Key details:
- **Passive only** — learns from DNS responses already on the wire; never
  sends its own lookups (no reverse-DNS latency, no traffic footprint)
- `observe()` accepts any packet and ignores non-DNS ones — call it
  unconditionally in the packet loop
- A/AAAA answers are mapped to the **queried domain** (first question),
  which reads better than CNAME chain tails
- Capped at 50k entries to bound memory on very long captures
- Unknown IPv6 endpoints fall back to bracketed `[addr]:port` form via
  `models::format_endpoint`

---

## Education (`education.rs`)

Plain-language teaching content, so someone who's never used a packet analyzer
can understand what they're seeing. UI-agnostic — just data and strings.

```rust
pub struct Lesson { title, summary, body, look_for }  // all &'static str
pub fn lesson(proto: &Protocol) -> Lesson             // per-protocol primer
pub fn all_lessons() -> Vec<(Protocol, Lesson)>        // teaching order
pub struct Term { term, meaning }
pub fn glossary() -> &'static [Term]                   // packet, port, TTL, SNI...
pub fn explain_packet(pkt: &Packet) -> &'static str    // one-line, context-aware
```

`explain_packet` inspects the summary before the protocol, so a TCP handshake,
a connection reset, a DNS query vs. response, or encrypted TLS each get a
tailored sentence rather than a generic protocol description.

---

## Firewall (`firewall.rs`)

OS-level traffic blocking by remote IP. Passive capture can't drop packets, so
blocking installs firewall rules that stop future traffic.

```rust
pub fn block(ip: IpAddr) -> Result<()>       // add netscope-block-<ip> rules
pub fn unblock(ip: IpAddr) -> Result<()>     // remove them
pub fn blocked_ips() -> BTreeSet<IpAddr>     // read current rules from the OS
pub fn unblock_all() -> Result<usize>        // remove every netscope rule
pub fn is_elevated() -> bool                 // can we install rules?
pub fn is_supported() -> bool                // true on Windows
pub fn rule_name(ip: IpAddr) -> String       // "netscope-block-<ip>"
```

Key details:
- **Windows**: two `netsh advfirewall` rules per IP (inbound + outbound, all
  profiles). Requires Administrator; `block`/`unblock` return a descriptive
  error otherwise.
- **Locale-independent**: `blocked_ips()` finds rules by the IP embedded in the
  rule name, never by parsing localized `netsh` output — works on any Windows
  language.
- **Elevation check** via the High-Integrity SID `S-1-16-12288` (constant
  across languages), not by attempting a privileged call.
- **Other platforms**: functions compile and return "Windows only"; `is_elevated`
  treats uid-0 as elevated.

---

## Stats Engine (`stats.rs`)

### `StatsEngine`
```rust
impl Default for StatsEngine  // new()
pub fn new() -> Self
pub fn record_packet(&mut self, packet: &Packet)
pub fn snapshot(&mut self) -> StatsSnapshot
```

### `StatsSnapshot`
```rust
pub struct StatsSnapshot {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub per_protocol: HashMap<Protocol, ProtocolStats>,
    pub current_bandwidth: f64,       // bytes/sec
    pub average_bandwidth: f64,       // bytes/sec (rolling 60s window)
    pub top_talkers_sent: Vec<(IpAddr, u64)>,
    pub top_talkers_received: Vec<(IpAddr, u64)>,
    pub top_domains: Vec<(String, u64)>,
}
```

### `ProtocolStats`
```rust
pub struct ProtocolStats {
    pub total_packets: u64,
    pub total_bytes: u64,
}
```

Bandwidth tracking uses 1-second windows with a 60-sample rolling buffer. Top talkers maintain top 10 senders/receivers by byte count using a HashMap + sort approach.

---

## Testing & Benchmarks

- **314 unit tests** covering all dissectors, models, stats, name cache, plus fuzz
- **Smoke benchmark**: `bench_dissect_throughput` — 10k synthetic packets, threshold >100k pkt/s (runs under `cargo test`)
- **Fuzz test**: `dispatch_random_garbage_never_panics` — 1000 random garbage packets
- **Fixtures**: 8 `.pcap` files in `fixtures/` generated by `tools/gen-fixtures`

### Continuous benchmarks (`benches/`) — ROADMAP §4.4

Criterion-based benchmarks live in `crates/core/benches/` and run in CI on
every push (quick mode, numbers land in the job log):

```bash
cargo bench --bench parse_throughput   # dissect() pkt/s — 10k mixed + per-protocol
cargo bench --bench filter_match       # 100k display-filter evaluations + per-filter cost
cargo bench --bench mem_usage          # heap footprint of 1M dissected packets
MEM_PACKETS=100000 cargo bench --bench mem_usage   # smaller run
```

Reference numbers (Windows x64, release):

| Benchmark | Result |
|---|---|
| `dissect()` mixed traffic | ~3.1 M packets/s |
| Display filter evaluation | ~32 M evals/s |
| 1M packets held in memory | ~269 MiB (≈281 B/packet) |
| Cloning 1M packets | +206 MiB — frame `Bytes` are shared, not copied (§4.2) |

### Profiling

```bash
cargo install flamegraph
# Flamegraph of the dissection hot path:
cargo flamegraph --bench parse_throughput -- --bench --profile-time 10
```
