# Contributing to netscope

Thanks for considering contributing! netscope is a community project and we welcome all contributions — bug reports, feature requests, documentation improvements, and code changes.

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/netscope.git`
3. Create a branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run lints: `cargo clippy -- -D warnings`
7. Format code: `cargo fmt`
8. Commit and push
9. Open a Pull Request

## Development Setup

See [docs/setup.md](docs/setup.md) for platform-specific prerequisites (Npcap on Windows, capabilities on Linux).

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

### Known issue: `cargo test --workspace` on Windows

On Windows, `cargo test --workspace` fails while linking/loading the
`netscope-desktop` lib test harness:

```
process didn't exit successfully: netscope_desktop_lib-<hash>.exe
(exit code: 0xc0000139, STATUS_ENTRYPOINT_NOT_FOUND)
```

This is not a netscope bug and not a broken test — the harness dies before any
test runs. `rfd`, pulled in through `tauri-plugin-dialog`, statically imports
`TaskDialogIndirect` from `comctl32.dll`. That symbol only exists in
Common-Controls **v6**, and a binary gets v6 only if it carries an application
manifest asking for it. `build.rs` attaches such a manifest to the *app binary
in release builds* — the test harness is neither, so the loader binds it to the
v5 `comctl32.dll` in System32, cannot resolve the import, and kills the process
at startup.

It only shows up under `--workspace` because building alongside the other
crates changes feature unification enough to pull the dialog path into the test
binary.

**Workaround** — run the crates separately, which is what CI does:

```bash
cargo test -p netscope-core -p netscope-tui
cargo test -p netscope-desktop   # passes on its own
```

A proper fix means embedding a Common-Controls v6 manifest into the test
harness, and needs two implementations — `/MANIFEST:EMBED` for the MSVC linker,
a `windres`-compiled resource object for the GNU one — so it should not be
merged until it has been verified on both toolchains.

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

## Questions?

Open a [Discussion](https://github.com/azzizefe/netscope/discussions) or join our community chat.
