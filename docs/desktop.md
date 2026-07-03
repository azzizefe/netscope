# Desktop App Reference

The netscope desktop app is built with **Tauri 2** — a Rust backend (`netscope-core` shared engine) + vanilla HTML/CSS/JS frontend.

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
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: String,
    length: usize,
    summary: String,
    raw: Vec<u8>,           // New: hex dump support
}
```

## Frontend (`frontend/`)

### `index.html`
- Interface `<select>` dropdown
- BPF filter `<input>`
- Start/Stop `<button>`
- Packet table (virtualized, last 500 visible)
- Detail panel (summary + hex dump)
- Tab bar (Packets / Dashboard)
- Status bar with keyboard shortcuts

### `styles.css`
- **Dark theme** with CSS custom properties
- Glassmorphism cards (`backdrop-filter: blur`)
- Protocol colors matching TUI
- Custom scrollbar styling
- Responsive layout (flexbox + grid)

### `app.js`
- **IPC**: `window.__TAURI__.core.invoke()` + `event.listen()`
- **Packet list**: virtualized (last 500 packets in `packetLog`, renders visible slice)
- **Stats**: client-side aggregation (protocol counts, bandwidth, top talkers, DNS domains)
- **Views**: tab switching (Packets / Dashboard)
- **Keyboard navigation**: `↑↓`, `Enter`, `h`, `Escape`
- **Graceful fallback**: if `__TAURI__` is undefined, logs to console (development outside Tauri)

## Backend State

```rust
struct CaptureState {
    engine: Option<CaptureEngine>,
    running: AtomicBool,
    packet_buffer: Vec<Packet>,   // Buffered for save_pcap
    _packet_count: u64,
}
```

- Managed by `tauri::Manager` as a `Mutex<CaptureState>`
- Packet buffer capped at 100,000 entries (drains oldest 50,000 when full)

## Build & Run

```bash
# Development
cd desktop/src-tauri
cargo tauri dev

# Production build
cd desktop/src-tauri
cargo tauri build --bundles "nsis"   # Windows
cargo tauri build --bundles "dmg"    # macOS
cargo tauri build --bundles "deb,appimage"  # Linux
```

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
