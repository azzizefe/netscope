# Working on netscope

netscope is **proprietary, closed-source software** (see [LICENSE](LICENSE)).
This document is the internal development guide for people who have been
granted access to the repository — it is not an invitation to contribute.

**Before you write code, read [SECURITY.md](SECURITY.md) §Confidentiality.**
The source, the fixtures, and anything derived from them are confidential.
Do not paste code into public issue trackers, forums, pastebins, or third-party
services, and do not push branches to any remote other than `origin`.

## Getting Started

1. Clone the repository: `git clone https://github.com/azzizefe/netscope.git`
2. Create a branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run lints: `cargo clippy -- -D warnings`
6. Format code: `cargo fmt`
7. Commit and push to `origin`
8. Open a Pull Request for review

## Development Setup

See [docs/setup.md](docs/setup.md) for platform-specific prerequisites (Npcap on Windows, capabilities on Linux).

After cloning, two build inputs are fetched or generated rather than committed:

```bash
# Windows only — the Npcap SDK the linker needs (its license does not permit
# redistribution, so it is downloaded instead of vendored)
.\tools\ensure-npcap-sdk.ps1

# Only needed to run the desktop frontend tests — builds the WASM filter module
./tools/build-wasm.sh          # Windows: .\tools\build-wasm.ps1
```

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run TUI (requires Npcap/sudo)
cargo run -p netscope-tui

# Test with offline pcap
cargo run -p netscope-tui -- -r fixtures/mixed.pcap --headless
```

### Fixed: `cargo test --workspace` on Windows

`cargo test --workspace` used to die on Windows before any test ran:

```
process didn't exit successfully: netscope_desktop_lib-<hash>.exe
(exit code: 0xc0000139, STATUS_ENTRYPOINT_NOT_FOUND)
```

`rfd`, pulled in through `tauri-plugin-dialog`, statically imports
`TaskDialogIndirect` from `comctl32.dll`. That symbol only exists in
Common-Controls **v6**, and a binary gets v6 only if it carries an application
manifest asking for it — which the test harness did not. It only showed up under
`--workspace`, because building alongside the other crates changes feature
unification enough to pull the dialog path into the test binary.

`desktop/src-tauri/build.rs` now links the manifest resource into the test
targets as well, so the full workspace run works. CI still invokes the crates
separately (`-p netscope-core -p netscope-tui -p netscope-server -p netscope-agent`,
then `-p netscope-desktop`) to keep Linux from having to install the seven Tauri
apt packages on every push.

### Timing-sensitive tests

Two tests assert a wall-clock packets/sec floor, so under `cargo test`'s
parallel load they measure how busy your machine is rather than what the code
costs. Both are `#[ignore]`d — run them deliberately, ideally on a quiet
machine:

```bash
cargo test --release bench_dissect_throughput  -- --ignored --nocapture
cargo test --release bench_pipeline_throughput -- --ignored --nocapture
```

## Code Style

- **No panics** — dissectors must never panic on malformed input. Use graceful fallbacks.
- **Human-readable summaries** — every packet should tell a story, not dump hex.
- **Follow existing patterns** — look at similar dissectors before adding a new one.
- **No unsafe code** unless absolutely necessary and justified.
- **Comments** are welcome but don't overdo it — code should be self-documenting.

### Rust conventions

- `cargo fmt` before committing
- `cargo clippy -- -D warnings` must pass
- Prefer `anyhow::Result` over custom error types
- Use `match` over `if let` chains for exhaustiveness checks
- Keep functions small and focused

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ICMP timestamp dissector
fix: handle truncated TCP options without panic
docs: update architecture diagram
test: add fuzz test for ARP dissector
refactor: extract DNS name parsing into helper
```

## Pull Request Process

1. Ensure tests pass and clippy is clean
2. Update docs if you're changing behavior
3. Add tests for new functionality
4. Keep PRs focused — one feature/fix per PR
5. PR title should follow conventional commits
6. Reference any related issues

## Adding a New Dissector

1. Create `crates/core/src/dissectors/my_protocol.rs`
2. Add `pub mod my_protocol;` to `crates/core/src/dissectors.rs`
3. Wire up the dispatch chain in the appropriate transport handler (TCP/UDP/IP)
4. Implement the dissector function returning `DissectedResult`
5. Add tests with realistic byte-level packet construction
6. Add a human-readable summary format (see [docs/dissectors.md](docs/dissectors.md))
7. Update the protocol color in `crates/tui/src/colors.rs`

## Project Structure

```
crates/core/          — Shared engine (capture, dissectors, models, stats)
crates/tui/           — Terminal UI
desktop/              — Tauri desktop app (future)
fixtures/             — Sample .pcap files
docs/                 — Documentation
tools/                — Utility crates (fixture generator)
```

## New files need a license header

Every source file starts with the two-line header from
[STYLE_GUIDE.md](STYLE_GUIDE.md) — SPDX identifier plus copyright — in the
comment syntax of that file type. A file without it ships without a notice of
who owns it, which is the one thing a proprietary codebase cannot afford:

```rust
// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
```

## Questions?

Ask the repository owner directly. Do not use public channels — see the
confidentiality note at the top.
