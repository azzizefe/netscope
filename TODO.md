# 🦀 netscope — Roadmap

> **Network analysis for humans.** Wireshark is powerful but overwhelming — netscope makes packet analysis simple, beautiful, and instant. TUI + Desktop.
>
> **Think:** `htop` killed `top`. `bat` killed `cat`. **netscope** kills Wireshark's complexity.
>
> **Platforms:** Windows, macOS, Linux
> **Stack:** Rust core + Tauri desktop app
> **License:** MIT

---

## 🎯 Design Philosophy

> These principles guide every decision. If a feature makes netscope more complex without clear value, it doesn't ship.

1. **Zero-config start** — Run it, it works. No setup, no config files, no 47-step wizard.
2. **Human-readable by default** — Show `google.com` not `142.250.74.46`. Show `HTTPS` not `TCP port 443 [SYN, ACK] seq=0x3fa2...`.
3. **Beautiful out of the box** — Dark theme, smooth colors, clean typography. First impression = ⭐.
4. **Progressive disclosure** — Simple view first, drill down for details only when you want.
5. **Fast** — Rust-native performance. Handles 10k+ packets/sec without breaking a sweat.

---

## Phase 0 — Project Scaffold

- [ ] `cargo init` + workspace structure:
  ```
  netscope/
  ├── crates/
  │   ├── core/          # capture engine, dissectors, models (shared)
  │   └── tui/           # terminal UI
  ├── desktop/           # Tauri app (Phase 6)
  ├── fixtures/          # sample .pcap files for testing
  └── Cargo.toml         # workspace root
  ```
- [ ] `.gitignore`, `LICENSE` (MIT), initial commit
- [ ] GitHub repo — **public from day one**
- [ ] Core dependencies:
  ```toml
  # crates/core
  pcap = "2"
  etherparse = "0.16"
  crossbeam-channel = "0.5"
  anyhow = "1"
  chrono = "0.4"
  dns-parser = "0.8"

  # crates/tui
  ratatui = "0.29"
  crossterm = "0.28"
  clap = { version = "4", features = ["derive"] }
  ```
- [ ] `cargo build` compiles on all platforms

---

## Phase 1 — Core Engine (`crates/core`)

> The brain of netscope. Shared between TUI and Desktop — write once, use everywhere.

### 1.1 Models
- [ ] `Protocol` enum — `Tcp`, `Udp`, `Dns`, `Http`, `Tls`, `Icmp`, `Arp`, `Unknown`
- [ ] `Packet` struct — timestamp, src, dst, protocol, length, human-readable summary
- [ ] `ConnectionInfo` struct — group related packets into flows (e.g., a full DNS lookup)

### 1.2 Capture Engine
- [ ] List available network interfaces
- [ ] Live capture on selected interface (promiscuous mode)
- [ ] BPF filter support
- [ ] Threaded capture → channel-based packet delivery
- [ ] Graceful start/stop (`AtomicBool`)
- [ ] Smart error messages ("Run with sudo" / "Install npcap on Windows")

### 1.3 Protocol Dissection
- [ ] Ethernet → IPv4/IPv6 → TCP/UDP/ICMP (via `etherparse`)
- [ ] ARP request/reply
- [ ] DNS query/response → extract domain name
- [ ] HTTP/1.x → method, path, status code
- [ ] TLS ClientHello → SNI (which website)
- [ ] Never crash on malformed packets — always graceful

### 1.4 Human-Readable Summaries ⭐
> **This is what makes netscope different from Wireshark.**

- [ ] DNS: `"DNS: google.com → 142.250.74.46"` (not raw hex)
- [ ] HTTPS: `"TLS → github.com (HTTPS)"` (SNI-based, not port numbers)
- [ ] HTTP: `"GET /api/users → 200 OK (1.2 KB)"` (one-line story)
- [ ] TCP: `"TCP Connection opened (3-way handshake)"` (not `SYN, SYN-ACK, ACK`)
- [ ] Unknown: `"Unknown protocol (74 bytes)"` (no panic, no crash)

### 1.5 Real-Time Stats Engine ⭐
> Wireshark buries this. We make it front-and-center.

- [ ] Live packet counter (total, per protocol)
- [ ] Bandwidth usage (bytes/sec, current + average)
- [ ] Top talkers — which IPs send/receive the most
- [ ] Top domains — most queried DNS domains
- [ ] Protocol distribution (% TCP vs UDP vs DNS vs ...)

---

## Phase 2 — TUI (`crates/tui`)

> A beautiful terminal UI. Not a Wireshark clone — a rethought experience.

### 2.1 Layout — Clean & Minimal

```
┌─────────────────────────────────────────────────────────┐
│  netscope  ▸ eth0  ●  Capturing    1,247 packets  12s  │  ← status bar
├─────────────────────────────────────────────────────────┤
│  #   Time     Source → Destination     Proto   Info     │
│  1   0.000s   192.168.1.5 → dns        DNS   google.com│  ← human readable!
│  2   0.012s   192.168.1.5 → google     TLS   HTTPS     │
│  3   0.034s   google → 192.168.1.5     TCP   1.4 KB    │
│ ▸4   0.089s   192.168.1.5 → github     TLS   HTTPS     │  ← selected
│  5   0.102s   github → 192.168.1.5     TCP   3.2 KB    │
├─────────────────────────────────────────────────────────┤
│  ▸ TLS ClientHello → github.com                        │  ← detail (collapsed)
│  ▸ TCP: 52341 → 443 [SYN]                              │
│  ▸ IPv4: 192.168.1.5 → 140.82.121.4, TTL=64           │
│  ▸ Ethernet: AA:BB:CC → DD:EE:FF                       │
├─────────────────────────────────────────────────────────┤
│  ↑↓ navigate  Tab panels  / filter  Space pause  ? help│  ← always visible
└─────────────────────────────────────────────────────────┘
```

- [ ] Status bar — interface, state, count, elapsed time
- [ ] Packet list — **human-readable by default** (not raw IPs everywhere)
- [ ] Detail panel — expandable layers (press Enter to expand/collapse)
- [ ] Hex dump — toggle with `h` (hidden by default — most users don't need it)
- [ ] Keybinding bar — always visible, no memorization needed

### 2.2 Views (Tab to switch) ⭐
> Wireshark only has a packet list. We have multiple views.

- [ ] **📋 Packets** — live packet stream (default view)
- [ ] **📊 Dashboard** — real-time stats, bandwidth graph, protocol pie chart
- [ ] **🌐 Connections** — group packets by flow/connection (see full conversations)
- [ ] **🔍 DNS Log** — all DNS queries in a clean list (which domains are being accessed)

### 2.3 Interaction — Minimal & Intuitive
- [ ] `↑/↓` or `j/k` — navigate
- [ ] `Enter` — expand/collapse packet details
- [ ] `Tab` — switch view (Packets → Dashboard → Connections → DNS)
- [ ] `/` — type a filter (smart autocomplete: `dns`, `http`, `ip:192.168...`)
- [ ] `Space` — pause / resume
- [ ] `h` — toggle hex dump
- [ ] `q` — quit
- [ ] `?` — help overlay

### 2.4 Colors — Protocol Identity
- [ ] TCP → `#4A9EF5` (Blue)
- [ ] UDP → `#45D1C5` (Teal)
- [ ] DNS → `#A78BFA` (Purple)
- [ ] HTTP → `#34D399` (Green)
- [ ] TLS/HTTPS → `#6EE7B7` (Light Green)
- [ ] ICMP → `#FBBF24` (Amber)
- [ ] ARP → `#9CA3AF` (Gray)
- [ ] Error/RST → `#F87171` (Red)
- [ ] Selected row → subtle highlight, not jarring

---

## Phase 3 — CLI Interface

> Power users get a clean CLI. No TUI needed for quick tasks.

- [ ] `netscope` — launch TUI (zero args = it just works)
- [ ] `netscope -i eth0` — capture on specific interface
- [ ] `netscope -f "tcp port 443"` — filtered capture
- [ ] `netscope -r capture.pcap` — analyze saved file
- [ ] `netscope -w output.pcap` — save capture to file
- [ ] `netscope -D` — list interfaces
- [ ] `netscope --headless` — stdout output, no TUI (pipe-friendly)
- [ ] `netscope --json` — JSON output (for scripting / integrations)

---

## Phase 4 — Quality & Polish

- [ ] Unit tests for every dissector (known bytes → expected output)
- [ ] Sample `.pcap` files in `fixtures/` for offline testing
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] Fuzz testing — throw garbage packets, never crash
- [ ] Performance benchmark — handle 10k+ pps without frame drops

---

## Phase 5 — Star-Worthy README & Docs ⭐

> **The README is the #1 reason people star a repo.** This is not optional polish — it's core product.

### 5.1 README Structure
- [ ] **Hero section** — project name, one-line description, badges (CI, version, license)
- [ ] **GIF/Video demo** — 15-second recording showing netscope in action
- [ ] **"Why netscope?"** — 3-bullet comparison vs Wireshark:
  - `✅ Human-readable` vs `❌ Raw hex dumps`
  - `✅ Works instantly` vs `❌ 47 menus to configure`
  - `✅ Single binary` vs `❌ 200MB installer`
- [ ] **Install** — one-liner per platform:
  ```bash
  # macOS
  brew install netscope

  # Linux
  curl -fsSL https://get.netscope.dev | sh

  # Windows
  winget install netscope
  # or download .exe from Releases
  ```
- [ ] **Quick start** — 3 lines max to get running
- [ ] **Keybinding table** — clean, scannable
- [ ] **Screenshots** — TUI + Desktop app (dark theme)
- [ ] **Contributing** link

### 5.2 Community Files
- [ ] `CONTRIBUTING.md` — how to contribute, code style, PR workflow
- [ ] `CODE_OF_CONDUCT.md` — Contributor Covenant
- [ ] `.github/ISSUE_TEMPLATE/` — bug report + feature request
- [ ] `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] `CHANGELOG.md`

### 5.3 GitHub Repo Polish
- [ ] Repository description — _"Network analysis for humans. A modern, simple alternative to Wireshark."_
- [ ] Topics/tags — `rust`, `networking`, `packet-analyzer`, `tui`, `wireshark-alternative`, `tauri`
- [ ] Social preview image (1280×640 — project logo + tagline)

---

## Phase 6 — Tauri Desktop App (`desktop/`)

> Same core engine, beautiful native GUI. For people who don't live in the terminal.

### 6.1 Setup
- [ ] `cargo tauri init` in `desktop/` directory
- [ ] Configure `tauri.conf.json` — name, identifier, window size
- [ ] Frontend: lightweight (vanilla HTML/CSS/JS or Svelte)
- [ ] Verify `cargo tauri dev` launches

### 6.2 GUI Design — Modern & Clean
- [ ] Dark theme by default (glassmorphism accents)
- [ ] Interface selector dropdown + Start/Stop button
- [ ] Packet table with protocol colors (same scheme as TUI)
- [ ] Collapsible detail panel (click to expand layers)
- [ ] Hex dump toggle (hidden by default)
- [ ] Filter bar with smart suggestions
- [ ] **Dashboard view** — live charts (bandwidth, protocol distribution, top talkers)
- [ ] **DNS view** — clean domain log

### 6.3 Backend Bridge (Tauri Commands)
- [ ] `list_interfaces`, `start_capture`, `stop_capture`
- [ ] `apply_filter`, `open_pcap`, `save_pcap`
- [ ] Real-time packet streaming via Tauri events
- [ ] Shared `crates/core` — zero logic duplication

### 6.4 Desktop Features
- [ ] Native file dialogs (open/save pcap)
- [ ] Keyboard shortcuts
- [ ] Auto-update via Tauri updater
- [ ] App icon + about dialog

---

## Phase 7 — CI/CD & Distribution

### 7.1 CI Pipeline
- [ ] `.github/workflows/ci.yml` — lint + test + build (Linux, macOS, Windows)
- [ ] Run on every push and PR

### 7.2 Release Pipeline
- [ ] `.github/workflows/release.yml` — triggered on version tag (`v*`)
- [ ] Build matrix:
  | Platform | TUI Binary | Desktop Installer |
  |----------|-----------|-------------------|
  | Windows | `netscope.exe` | `netscope-setup.exe` (NSIS) |
  | macOS | `netscope` (universal) | `netscope.dmg` |
  | Linux | `netscope` (x86_64) | `netscope.AppImage` + `.deb` |
- [ ] Auto-attach all artifacts to GitHub Release
- [ ] Generate changelog from commits

### 7.3 Package Managers (post-launch)
- [ ] `brew tap` formula (macOS/Linux)
- [ ] AUR package (Arch Linux)
- [ ] `winget` manifest (Windows)
- [ ] Install script: `curl -fsSL https://get.netscope.dev | sh`

---

## ✅ Definition of Done

### Must Have (v0.1.0)
- [ ] Live capture works with real-time colored packet stream
- [ ] Human-readable summaries (DNS domains, TLS SNI, HTTP paths)
- [ ] Dashboard view with live stats
- [ ] DNS log view
- [ ] `.pcap` file read/write
- [ ] BPF filter support
- [ ] Beautiful TUI that people want to screenshot
- [ ] Desktop app with `.exe` / `.dmg` / `.AppImage` downloads
- [ ] README with GIF demo and one-liner install
- [ ] CI green on all platforms

### Not in v1 (Keep it simple)
- ❌ Deep packet inspection beyond basic L7
- ❌ Packet editing / injection
- ❌ Complex display filter language (keep it simple search)
- ❌ Plugin system
- ❌ Remote capture
- ❌ Decryption (SSL/TLS key log)

---

## 🧭 Execution Order

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 → Phase 7
   ↑          ↑          ↑                              ↑          ↑          ↑
Scaffold   Engine     TUI                         README/Docs   Desktop    Ship it
                   (people can                    (star magnet)  (.exe)
                    use it here)
```

> After Phase 2, you have a working product. Everything after is polish + distribution.

---

## 🔧 Quick Reference

### TUI
| Task | Command |
|------|---------|
| Launch | `netscope` |
| Specific interface | `netscope -i eth0` |
| With filter | `netscope -f "tcp port 443"` |
| Read pcap | `netscope -r file.pcap` |
| Save capture | `netscope -w output.pcap` |
| List interfaces | `netscope -D` |
| JSON output | `netscope --headless --json` |

### Desktop
| Task | Command |
|------|---------|
| Dev mode | `cargo tauri dev` |
| Build installer | `cargo tauri build` |

### Development
| Task | Command |
|------|---------|
| Build all | `cargo build` |
| Release build | `cargo build --release` |
| Test | `cargo test` |
| Lint | `cargo clippy -- -D warnings` |
| Format | `cargo fmt` |
| Permissions (Linux) | `sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/netscope` |