# Setup Guide

## Prerequisites

- **Rust** 1.85+ (install via [rustup](https://rustup.rs))
- **C toolchain** (for pcap native dependencies)

## Platform Setup

### Windows — Npcap + MinGW

1. Install [Npcap](https://npcap.com) (check "Install in WinPcap API-compatible Mode")
2. Install MSYS2 + MinGW-w64:
   ```
   winget install MSYS2.MSYS2
   ```
   Then in MSYS2 terminal:
   ```
   pacman -S mingw-w64-x86_64-toolchain
   ```
3. Add to `PATH`:
   ```powershell
   $env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
   ```
4. Set `LIBPCAP_LIBDIR` for compilation:
   ```powershell
   $env:LIBPCAP_LIBDIR = "$env:TEMP\npcap-sdk\Lib\x64"
   ```
5. Copy 64-bit `wpcap.dll` + `Packet.dll` to `target/debug/deps/` for test runtime, or add their directory to `PATH`.

### Linux
```bash
sudo apt install libpcap-dev     # Debian/Ubuntu
sudo dnf install libpcap-devel   # Fedora
# For desktop app only:
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev
```

### macOS
libpcap is built-in. Run with `sudo` for live capture. No additional setup needed.

## Build

```bash
# Build all workspace crates (core + tui + fixtures)
cargo build

# Build specific crate
cargo build -p netscope-core
cargo build -p netscope-tui

# Build desktop (requires Tauri CLI)
cargo build -p netscope-desktop

# Release build
cargo build --release

# Run the TUI
cargo run -p netscope-tui -- --help

# Desktop dev mode
cd desktop/src-tauri && cargo tauri dev
```

## Test

```bash
# Run all tests
cargo test -p netscope-core -p netscope-tui

# Run with npcap DLLs on Windows
$env:PATH = "C:\msys64\mingw64\bin;$env:TEMP\npcap-dll64;$env:PATH"
$env:LIBPCAP_LIBDIR = "$env:TEMP\npcap-sdk\Lib\x64"
cargo test -p netscope-core
```

## Lint & Format

```bash
cargo clippy --workspace --exclude netscope-desktop -- -D warnings
cargo fmt --check
```

## Verify Offline

Test with sample pcap files:

```bash
# Headless (plain text)
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless

# Headless (JSON)
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --json

# With BPF filter
cargo run -p netscope-tui -- -r fixtures/mixed.pcap -f "tcp" --headless

# Read + write simultaneously
cargo run -p netscope-tui -- -r fixtures/mixed.pcap -w output.pcap --headless

# List interfaces (no live capture needed)
cargo run -p netscope-tui -- -D
```

## CI Environment

For CI/CD (GitHub Actions), the following is handled automatically:

- **Windows**: Npcap SDK downloaded from `https://npcap.com/dist/npcap-sdk-1.13.zip`
- **Linux**: `libpcap-dev` installed via apt
- **Desktop**: Tauri CLI installed via `taiki-e/install-action@v2` with `tool: cargo-tauri2`
- **All platforms**: `cargo build -p netscope-core -p netscope-tui` (skips desktop for CI speed)
- **Release**: Full matrix including desktop bundles

## Troubleshooting

| Error | Solution |
|-------|----------|
| `dlltool.exe: program not found` | Add MinGW bin to PATH: `$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"` |
| `STATUS_DLL_NOT_FOUND` | Add npcap DLL dir to PATH: `$env:PATH = "$env:TEMP\npcap-dll64;$env:PATH"` |
| `Failed to open interface` | Ensure Npcap is installed (Windows) or run with sudo (Linux/macOS) |
| `Invalid BPF filter` | Check filter syntax: `tcp port 443` (not `tcp.port == 443`) |
| `Tauri build fails: dialog:file-open` | Update `capabilities/default.json` — use `dialog:default` only |
