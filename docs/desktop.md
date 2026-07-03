# Desktop App Reference

The netscope desktop app is built with **Tauri 2** — a Rust backend (`netscope-core` shared engine) + vanilla HTML/CSS/JS frontend. A single native window, no terminal required.

---

## For users: what you need to run it

netscope is a **network capture tool**, so it needs a little more than a normal
app. Here's everything, in order:

| # | Requirement | Why | How |
|---|-------------|-----|-----|
| 1 | **Npcap** (Windows) | The driver that lets any app read network packets. Without it netscope sees zero traffic. | Download from [npcap.com](https://npcap.com), install with **"WinPcap API-compatible mode"** ticked. Free. |
| 2 | **WebView2** (Windows) | Renders the app's window. | Pre-installed on Windows 10/11. If missing: [Microsoft WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/). |
| 3 | **Run as Administrator** | Capturing packets and installing firewall block rules both need elevated rights. | Right-click netscope → **Run as administrator**. Without it, capture may be empty and blocking is disabled (you'll see a `⚠ not admin` badge). |

That's it — no accounts, no config files, no separate runtime. On **macOS** and
**Linux** there's no Npcap: macOS needs no driver (just run with `sudo` or grant
BPF access), Linux needs `libpcap` and either `sudo` or the `cap_net_raw`
capability on the binary.

### Installing (once released)

Download the installer for your OS from the [Releases page](https://github.com/azzizefe/netscope/releases):

| OS | File | Notes |
|----|------|-------|
| Windows | `netscope_x.y.z_x64-setup.exe` (NSIS) | Install Npcap first (step 1 above). |
| macOS | `netscope_x.y.z_universal.dmg` | Drag to Applications. |
| Linux | `.AppImage` or `.deb` | AppImage: `chmod +x` then run. |

### First run

1. Launch netscope (as administrator on Windows).
2. Pick your network interface from the dropdown (it defaults to a sensible one — usually your Wi-Fi/Ethernet).
3. Click **▶ Start**. Packets start streaming immediately.
4. Open the **Connections** tab to see where your traffic is going — and click **⛔ Block** on anything you want to cut off.
5. New to all this? Open the **🎓 Learn** tab.

---

## Architecture

```
┌─────────────────────────────────────┐
│  Tauri Frontend (WebView)           │
│  index.html / styles.css / app.js   │
│                                     │
│  ├── Interface selector             │
│  ├── Start / Stop buttons           │
│  ├── Packet table (colored rows)    │
│  ├── Detail panel (summary + hex)   │
│  └── Dashboard (stats + charts)     │
└──────────────┬──────────────────────┘
               │ invoke() / event.listen()
               ▼
┌─────────────────────────────────────┐
│  Tauri Backend (Rust)               │
│  src-tauri/src/lib.rs               │
│                                     │
│  ├── list_interfaces()              │
│  ├── start_capture()                │
│  ├── stop_capture()                 │
│  ├── open_pcap()                    │
│  └── save_pcap()                    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  netscope-core                      │
│  CaptureEngine / Dissectors / Stats │
└─────────────────────────────────────┘
```

## Backend Commands (`lib.rs`)

### `list_interfaces() -> Vec<InterfaceInfo>`
Returns available network interfaces with name + description.

### `is_elevated() -> bool`
Whether the app can install firewall rules. Drives the `⚠ not admin` badge.

### `list_blocked() -> Vec<String>` / `block_ip(ip)` / `unblock_ip(ip)`
Read, add, and remove netscope firewall block rules (via `core::firewall`).
`block_ip`/`unblock_ip` validate the IP and return a descriptive error string
to the frontend on failure (e.g. not elevated).

### `get_lessons() -> Vec<LessonInfo>` / `get_glossary() -> Vec<TermInfo>`
Serve the beginner content from `core::education` to the Learn tab, so the
lessons have a single source of truth shared with the TUI.

### `start_capture(interface, filter?, output_path?)`
- Creates `CaptureEngine`, starts live capture
- Spawns packet forwarding thread
- Streams packets to frontend via `app.emit("packet", PacketInfo)`
- Forwarding thread exits when capture channel disconnects

### `stop_capture()`
Stops the capture engine (sets `AtomicBool`, joins capture thread).

### `open_pcap(path)`
- Reads pcap file offline via `CaptureEngine::start_offline()`
- Streams all packets to frontend
- Emits `capture-finished` event when done

### `save_pcap(path)`
- Writes buffered packets to a pcap file
- Manual pcap format writer (24-byte global header + per-packet 16-byte headers)
- Not yet available: returns error suggesting `-w` CLI flag

### `PacketInfo` (emitted to frontend)
```rust
struct PacketInfo {
    timestamp: String,
    src_addr: Option<String>,
    dst_addr: Option<String>,
    src_host: Option<String>,   // hostname learned via passive DNS
    dst_host: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: String,
    length: usize,
    summary: String,
    explanation: String,        // plain-language "what is this?"
    raw: Vec<u8>,               // for the hex dump
}
```

The forwarder thread feeds each packet through a shared `NameCache` before
building `PacketInfo`, so hostnames appear the moment their DNS response is
seen. `explanation` comes from `education::explain_packet`.

## Frontend (`frontend/`)

### `index.html`
- Interface `<select>` dropdown, BPF filter `<input>`, Start/Stop buttons
- `⚠ not admin` elevation badge
- Four tabs: **Packets / Connections / Dashboard / 🎓 Learn**
- Packets: table (last 500 visible) + detail panel with the `ℹ` explanation and hex dump
- Connections: flows grouped by remote server, with per-row **Block/Unblock**
- Learn: lesson cards + glossary fetched from the backend

### `styles.css`
- **Dark theme** with CSS custom properties
- Glassmorphism cards (`backdrop-filter: blur`)
- Protocol colors matching TUI
- Custom scrollbar styling
- Responsive layout (flexbox + grid)

### `app.js`
- **IPC**: `window.__TAURI__.core.invoke()` + `event.listen()`
- **Packet list**: renders the last 500 of up to 10k buffered packets; hostnames shown when known
- **Connections**: aggregates packets into flows client-side (bidirectional key + transport, mirroring `core::flows`), tracks the server hostname, and blocks by server IP
- **Blocking**: `block_ip`/`unblock_ip`; the blocked set is loaded at startup via `list_blocked` so rules from earlier sessions show as blocked
- **Stats**: client-side aggregation (protocol counts, top talkers, top domains)
- **Learn**: cards + glossary from `get_lessons`/`get_glossary`
- **Keyboard**: `Tab` cycles views, `↑↓/jk` navigate packets, `Esc` closes detail

## Backend State

```rust
struct CaptureState {
    engine: Option<CaptureEngine>,
    running: AtomicBool,
    packet_buffer: Vec<Packet>,   // Buffered for save_pcap
    names: NameCache,             // passive DNS hostname cache
    _packet_count: u64,
}
```

- Managed by `tauri::Manager` as a `Mutex<CaptureState>`
- Packet buffer capped at 100,000 entries (drains oldest 50,000 when full)

## Build & Run

```bash
# Quickest: run the app straight from source (frontend is static, no bundler)
cargo run -p netscope-desktop
# On Windows, launch the built exe "as administrator" for capture + blocking:
#   target/debug/netscope-desktop.exe

# Development with hot-reload tooling
cd desktop/src-tauri
cargo tauri dev

# Production installer
cd desktop/src-tauri
cargo tauri build --bundles "nsis"   # Windows  → .exe setup
cargo tauri build --bundles "dmg"    # macOS    → .dmg
cargo tauri build --bundles "deb,appimage"  # Linux
```

Because the frontend is plain HTML/CSS/JS (no npm build step), `cargo run
-p netscope-desktop` launches the full app — handy for development.

### Prerequisites
- **Rust** 1.85+
- **Tauri CLI**: `cargo install tauri-cli --version "^2"` (or use `taiki-e/install-action` in CI)
- **Windows**: Npcap SDK (`LIBPCAP_LIBDIR`), WebView2 (pre-installed on Win10+)
- **Linux**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libjavascriptcoregtk-4.1-dev`, `libsoup-3.0-dev`, `libpcap-dev`

## Icons

Generated from `icons/icon-source.png` (1024×1024, dark background with purple circle + white "N"):

| Format | Files |
|--------|-------|
| PNG | `32x32.png`, `64x64.png`, `128x128.png`, `128x128@2x.png`, `icon.png` |
| ICO | `icon.ico` |
| ICNS | `icon.icns` |
| Store | `StoreLogo.png`, `Square*.png` |

Regenerate with: `cargo tauri icon icons/icon-source.png` (run from `desktop/src-tauri/`)

## CI/CD (Desktop Bundle)

In the release workflow (tag `v*`):
1. Install Tauri CLI via `taiki-e/install-action@v2` with `tool: cargo-tauri2`
2. Build: `cargo tauri build --ci --bundles "${{ matrix.bundles }}"`
3. Upload bundle artifacts to GitHub Release

| Platform | Bundles | Artifact |
|----------|---------|----------|
| Windows | NSIS | `.exe` installer |
| macOS | DMG | `.dmg` disk image |
| Linux | DEB + AppImage | `.deb` + `.AppImage` |
