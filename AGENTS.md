# netscope — Agents Guide

## Build & Test

```bash
# Build all workspace crates
cargo build

# Build specific crates
cargo build -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent

# Run all tests (use -p to target specific crates)
cargo test -p netscope-core -p netscope-tui -p netscope-server -p netscope-agent
cargo test -p netscope-desktop        # Windows/macOS only

# Lint (deny warnings)
cargo clippy --workspace --exclude netscope-desktop -- -D warnings

# Format check
cargo fmt --check
cargo fmt                              # auto-format

# Benchmarks
cargo bench -p netscope-core --bench parse_throughput -- --quick
cargo bench -p netscope-core --bench filter_match -- --quick

# WASM (for frontend tests)
cargo build -p netscope-wasm --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir desktop/frontend/wasm target/wasm32-unknown-unknown/release/netscope_wasm.wasm

# Frontend tests (vitest)
cd desktop/frontend-tests && npm ci && npm test

# Run TUI (requires admin/Npcap)
cargo run -p netscope-tui
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless   # offline
```

## Workspace Crates

| Crate | Description |
|---|---|
| `netscope-core` | Capture engine, protocol dissectors, stats, name resolution |
| `netscope-tui` | Terminal UI (ratatui) |
| `netscope-wasm` | WASM filter module (wasm32-unknown-unknown) |
| `netscope-server` | gRPC server (requires protoc) |
| `netscope-agent` | Sensor agent |
| `netscope-desktop` | Tauri desktop app (src-tauri/) |

## Prerequisites (per platform)

- **Linux**: `sudo apt install libpcap-dev`
- **Windows**: Npcap SDK (in `npcap-sdk/` or downloaded); LIBPCAP_LIBDIR
- **macOS**: libpcap via Xcode CLT (no extra step)
- **All**: `protoc` on PATH (for netscope-server build.rs)

## Project Conventions

- Rust edition 2021, proprietary license (see `LICENSE`) — this repository is **not** open source; never publish crates, snippets or fixtures outside `origin`
- Clippy lint config in root `Cargo.toml` under `[workspace.lints.clippy]`; each crate opts in with `[lints] workspace = true`
- `desktop/frontend/` — Tauri web UI (svelte/vite); `desktop/frontend-tests/` — vitest tests
- `fixtures/` — offline pcap files for testing
- `tools/gen-fixtures/` — pcap generator tool
- `cargo test --workspace` may fail on Windows due to comctl32 manifest issue (use `-p` per crate)
