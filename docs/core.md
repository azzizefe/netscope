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

### `CaptureEngine`
Manages a background capture thread with `AtomicBool` stop flag.

```rust
impl Default for CaptureEngine  // new()
pub fn new() -> Self
pub fn start_live(
    &mut self,
    interface: &str,
    bpf_filter: Option<&str>,
    output_path: Option<&str>,     // NEW: simultaneous savefile
    packet_tx: Sender<Packet>,
) -> Result<()>
pub fn start_offline(
    &mut self,
    filepath: &str,
    bpf_filter: Option<&str>,
    output_path: Option<&str>,     // NEW: simultaneous savefile
    packet_tx: Sender<Packet>,
) -> Result<()>
pub fn stop(&mut self)
pub fn is_running(&self) -> bool
```

Key details:
- Live: promiscuous mode, snaplen 65535, 1-second timeout
- BPF filter compiles before capture starts; returns descriptive error on invalid filter
- `output_path` (new in Phase 3) creates a `pcap::Savefile` — packets are written as they arrive
- Savefile errors are logged to stderr (not silently swallowed)
- Thread is named `"capture"` for debugging
- Drop calls `stop()` automatically

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
| `icmp` | IP addrs | `"ICMP message"` |
| `arp` | Ethernet payload | `"ARP Request — Who has 192.168.1.1? Tell 192.168.1.2 (aa:bb:cc:dd:ee:ff)"`, `"ARP Reply — 192.168.1.1 is at aa:bb:cc:dd:ee:ff"` |
| `dns` | UDP port 53 | `"DNS Query — google.com (1)"`, `"DNS Response — google.com → 142.250.74.46 (2 answers)"`, `"DNS Response — google.com → 2607:f8b0::1 (AAAA)"` |
| `http` | TCP port 80 | `"HTTP GET /api/users (HTTP/1.1)"`, `"HTTP POST /login (HTTP/1.1)"`, `"HTTP 200 OK (1234 bytes)"` |
| `tls` | TCP port 443 | `"TLS — github.com (HTTPS)"` (SNI), `"TLS Handshake (no SNI)"`, `"TLS — N bytes of encrypted data"` |

### Error handling
Every dissector returns gracefully on malformed input — no panics. Fuzz test validates 1000 random garbage packets produce zero panics.

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

- **58 unit tests** covering all dissectors, models, stats, plus fuzz
- **Benchmark**: `bench_dissect_throughput` — 10k synthetic packets, threshold >100k pkt/s
- **Fuzz test**: `dispatch_random_garbage_never_panics` — 1000 random garbage packets
- **Fixtures**: 8 `.pcap` files in `fixtures/` generated by `tools/gen-fixtures`
