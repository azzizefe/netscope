# TUI Crate Reference

The `netscope-tui` crate provides the terminal user interface using `ratatui` + `crossterm`. Built on `clap` for CLI argument parsing.

## CLI Interface

```
Usage: netscope-tui [OPTIONS]

  -i, --interface <IFACE>    Interface to capture on
  -r, --read <FILE>          Read from a pcap file
  -w, --write <FILE>         Save capture to pcap file
  -f, --filter <BPF>         BPF filter (e.g. "tcp port 443")
  -D, --list-interfaces      List available interfaces
      --headless             Plain text output to stdout
      --json                 JSON Lines output (implies --headless)
  -h, --help                 Print help
```

### Run Modes

| Condition | Behavior |
|-----------|----------|
| No flags | Launch TUI; auto-selects the connected physical interface (loopback and virtual adapters like WAN Miniport are skipped) |
| `-r <file>` | Read pcap, then launch TUI or --headless |
| `-D` | Print interfaces, exit |
| `--headless` | Print packets as formatted text, exit |
| `--json` | Print packets as JSON Lines, exit |
| `-i <iface>` + TUI | Live capture on specified interface |
| `-r <file> -w <out>` | Read + write pcap simultaneously |

## Main Loop (`main.rs`)

1. Parse CLI args with `clap`
2. Dispatch:
   - `-D` → call `list_interfaces()`, print table, exit
   - `--headless` or `--json` → start capture, format output per packet, exit when done
   - Default → enter TUI event loop
3. TUI setup: enter alternate screen, enable raw mode, start capture thread

## App State (`app.rs`)

```rust
pub struct App {
    pub packets: VecDeque<Packet>,    // Ring buffer, max 10_000
    pub filter_text: String,          // Free-text filter
    pub selected: usize,              // Selected row index
    pub view: View,                   // Current view tab
    pub stats: StatsSnapshot,         // Latest stats
    pub dns_log: Vec<Packet>,         // Filtered DNS packets
    pub paused: bool,                 // Pause live capture
    pub detail_open: bool,            // Detail panel expanded
    pub hex_open: bool,               // Hex dump visible
    pub show_help: bool,              // Help overlay
    pub status: String,               // Status bar message
}
```

### Filtering

Characters are typed directly (no `/` prefix). Case-insensitive substring match against:
- `pkt.summary`
- `pkt.protocol.to_string()`
- `pkt.src_addr`, `pkt.dst_addr` (rendered as `String`)
- **learned hostnames** — typing `google` matches packets whose IP resolved
  to a `*google*` domain via the passive DNS cache

Controls: `Esc` clears filter, `Backspace` removes last character.

### Hostname display

The app feeds every packet through `NameCache::observe()`. Wherever an
address appears — packet list, detail panel, connections view, headless
output — a learned hostname is shown instead of the raw IP:

```
192.168.1.58:51884 → example.com:80    (instead of → 93.184.216.34:80)
```

The detail panel shows both: `Destination: 93.184.216.34 (example.com)`.

## Views

### 1. Packets View (`views/packets.rs`)
- Table with columns: `#`, `Time`, `Source → Destination`, `Proto`, `Info`
- Protocol-colored rows
- Selected row highlighted with `SELECTED_BG` (`#1E3A5F`)
- Collapsible detail panel shows: timestamp, addresses, ports, length, raw summary
- Hex dump panel (togglable with `h`)
- Keybinding bar at bottom

### 2. Dashboard View (`views/dashboard.rs`)
Four panels:
1. **Stats**: total packets/bytes, current/average bandwidth
2. **Protocol Distribution**: sorted by count, color-coded horizontal bars
3. **Bandwidth**: scaled bar (`━` chars, max 10 Mbps)
4. **Top Talkers**: split 50/50 — top 5 senders (left), top 5 receivers (right)

### 3. Connections View (`views/connections.rs`)
Conversations grouped by flow (5-tuple). Columns: `#`, `Client`, `Server`,
`Proto`, `Pkts`, `⇄` (per-direction packet counts), `Bytes`, `Duration`,
`Last activity`. Endpoints show hostnames when known.

### 4. DNS Log View (`views/dns_log.rs`)
- Filters `app.packets` where `protocol == Dns`
- Columns: `#`, `Time`, `Query / Response`, `Details`
- Query/Response detected via `summary.contains("Query")`
- Static (no interactive selection)

## Protocol Colors (`colors.rs`)

| Protocol | Color | Hex |
|----------|-------|-----|
| TCP | Blue | `#4A9EF5` |
| UDP | Teal | `#45D1C5` |
| DNS | Purple | `#A78BFA` |
| HTTP | Green | `#34D399` |
| TLS | Mint | `#6EE7B7` |
| ICMP | Amber | `#FBB224` |
| ARP | Gray | `#9CA3AF` |
| Unknown | Red | `#F87171` |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate packet list |
| `Enter` | Expand/collapse packet details |
| `Tab` / `Shift+Tab` | Switch views (Packets → Dashboard → Connections → DnsLog) |
| *(any character)* | Filter packets (free text — type directly) |
| `Space` | Pause / resume capture |
| `h` | Toggle hex dump |
| `?` | Help overlay |
| `Esc` | Clear filter / close help |
| `q` | Quit |

## Headless Module (`headless.rs`)

### `format_plain(pkt: &Packet, names: &NameCache) -> String`
```
[2024-01-01 12:00:00.000] 10.0.0.1:12345 → example.com:80  HTTP  91B  HTTP GET / (HTTP/1.1)
```
Hostnames learned from captured DNS responses replace raw IPs. IPv6
endpoints are bracketed: `[2001:db8::1]:443`. When no interface is given,
the auto-selected one is announced on stderr (`Capturing on: ...`) so stdout
stays pipe-clean.

### `format_json(pkt: &Packet) -> String`
```json
{"timestamp":"2024-01-01T12:00:00.000Z","src":"10.0.0.1","dst":"10.0.0.2","src_port":12345,"dst_port":80,"protocol":"HTTP","length":91,"summary":"HTTP GET / (HTTP/1.1)"}
```

JSON output uses `--json` flag, plain text with `--headless`. Both imply no TUI rendering.
