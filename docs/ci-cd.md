# CI/CD Pipeline

## CI Workflow (`.github/workflows/ci.yml`)

Triggered on every push to `main` and pull requests.

### Jobs

#### 1. lint (Ubuntu)
```yaml
- cargo clippy --workspace --exclude netscope-desktop -- -D warnings
- cargo fmt --check
```

#### 2. test (matrix: Ubuntu, macOS, Windows)
For each OS:
- Install pcap dependency (libpcap-dev on Linux, Npcap SDK on Windows)
- `cargo build -p netscope-core -p netscope-tui`
- `cargo test -p netscope-core -p netscope-tui`

### Caching
Uses `Swatinem/rust-cache@v2` for faster subsequent runs.

### Concurrency
Cancels in-progress runs for the same branch to save resources.

## Release Workflow (`.github/workflows/release.yml`)

Triggered on tags matching `v*` (e.g., `v0.1.0`).

### Jobs

#### 1. TUI Binary (matrix)

| OS | Target | Binary |
|----|--------|--------|
| ubuntu-latest | `x86_64-unknown-linux-gnu` | `netscope` |
| macos-latest | `aarch64-apple-darwin` | `netscope` |
| windows-latest | `x86_64-pc-windows-msvc` | `netscope.exe` |

Builds with `--release` and `--target`. Uploads as artifact `netscope-<target>`.

#### 2. Desktop Installer (matrix)

| OS | Bundles | Artifact Prefix |
|----|---------|-----------------|
| ubuntu-latest | `deb,appimage` | `netscope-desktop-Linux` |
| macos-latest | `dmg` | `netscope-desktop-macOS` |
| windows-latest | `nsis` | `netscope-desktop-Windows` |

Steps:
1. Install system deps (Linux: webkit2gtk, gtk3, etc.)
2. Install Npcap SDK (Windows)
3. Install Tauri CLI via `taiki-e/install-action@v2` with `tool: cargo-tauri2`
4. `cargo tauri build --ci --bundles "<bundles>"`
5. Upload bundle artifacts

#### 3. Create Release
Depends on both TUI and desktop jobs. Downloads all artifacts and creates a GitHub Release via `softprops/action-gh-release@v2` with `generate_release_notes: true`.

## Workflow Files

- `.github/workflows/ci.yml` — 56 lines, 2 jobs
- `.github/workflows/release.yml` — 148 lines, 3 jobs

## Adding a New Platform

1. Add new entry to the matrix in both workflows
2. Add platform-specific pcap deps (if needed)
3. For desktop: add Tauri bundle target in `tauri.conf.json`

## Manual Release

```bash
# Tag and push
git tag -a v0.1.0 -m "netscope v0.1.0"
git push origin v0.1.0

# GitHub Actions will:
# 1. Build TUI binaries for all platforms
# 2. Build desktop installers for all platforms
# 3. Create a GitHub Release with all assets
```
