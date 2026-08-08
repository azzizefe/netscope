# Fuzzing netscope's packet dispatch

One target, `parse_packet_fuzz`, driving `netscope_core::dissectors::dissect()`
with arbitrary bytes. That function is the single door every captured frame goes
through — Ethernet, IP, the transport, then whichever of 500-odd application
dissectors the port or the framing selects — and every layer of it is parsing
input an attacker chooses. A panic there kills the analyser mid-capture, and on
a live capture the packets that arrive while it is down are gone.

## Running it

**Requires a nightly toolchain, and on Windows the MSVC one specifically, with
the ASan runtime on PATH.** Both requirements are covered below; neither failure
mode says what is wrong, which is the only reason they are worth this much text.

Verified working on this repo: 5,000 runs, no crash, reaching `dispatch_l3`,
`ip::dissect_ipv4`, `dispatch_transport` and `snap::dissect_snap`. Note the
first build takes roughly 40 minutes — netscope-core in release is large.

```bash
cargo +nightly-x86_64-pc-windows-msvc fuzz run parse_packet_fuzz --target x86_64-pc-windows-msvc
```

On Linux or macOS the target flag is unnecessary:

```bash
cargo +nightly fuzz run parse_packet_fuzz
```

Bounded run, which is what you want when checking a change rather than hunting:

```bash
cargo +nightly fuzz run parse_packet_fuzz -- -max_total_time=60
```

### And on Windows, the sanitiser runtime has to be on PATH

cargo-fuzz builds with AddressSanitizer, and on Windows that runtime is a DLL
rather than something linked in. Without it the binary builds fine, links fine,
and then refuses to start:

```text
error: process didn't exit successfully: `...\parse_packet_fuzz.exe ...`
       (exit code: 0xc0000135, STATUS_DLL_NOT_FOUND)
```

`0xc0000135` names no DLL, so there is nothing in that message to act on. The
one it wants is `clang_rt.asan_dynamic-x86_64.dll`, which ships with the MSVC
toolchain:

```powershell
$asan = "C:\Program Files\Microsoft Visual Studio\<ver>\<edition>\VC\Tools\MSVC\<toolset>\bin\Hostx64\x64"
$env:PATH = "$asan;$env:PATH"
```

An LLVM install has a copy too, under `lib\clang\<n>\lib\windows\`. Confirm what
a built target actually wants with:

```bash
objdump -p fuzz/target/x86_64-pc-windows-msvc/release/parse_packet_fuzz.exe | grep "DLL Name"
```

Linux does not need any of this — the runtime comes with the toolchain.

### Why the toolchain matters

The default toolchain in this repo is `x86_64-pc-windows-gnu`, and cargo-fuzz
**cannot** work there. `libfuzzer-sys` compiles a bundled copy of libFuzzer,
whose Windows support is written for MSVC:

```text
libfuzzer\FuzzerExtFunctionsWindows.cpp:41:11: error: expected constructor,
destructor, or type conversion before '(' token
   41 |   __pragma(comment(linker, "/alternatename:" ...
```

`__pragma(comment(linker, ...))` is MSVC syntax; GCC rejects it. This is a
property of libFuzzer, not of anything in netscope, and there is no flag that
works around it — use the MSVC nightly.

## Relationship to the unit tests

`dissectors::robustness` already sweeps malformed payloads across every
dispatched port and the structural fall-through, deterministically, on every
`cargo test`. This is the other half: coverage-guided search over inputs nobody
thought to write down, including the link-layer and IP header fields those
sweeps hold fixed.

Neither replaces the other. The sweeps are a regression guard that runs in
seconds; this is an open-ended hunt you leave running.

## If it finds something

libFuzzer writes the input to `fuzz/artifacts/parse_packet_fuzz/`. Reproduce it
with:

```bash
cargo +nightly fuzz run parse_packet_fuzz fuzz/artifacts/parse_packet_fuzz/crash-<hash>
```

Then add those bytes as a case in the relevant dissector's tests before fixing
it, so the crash cannot come back without the suite noticing.

## What was here before

`cargo fuzz init`'s template, unchanged:

```rust
fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
});
```

It built, ran, reported coverage and exercised nothing, for as long as anyone
cared to leave it running. The manifest was broken in two ways besides: no
`[workspace]` table, so cargo refused to build the package at all, and
`netscope-core` pointed at `..` — the workspace root, a virtual manifest with no
`[package]` in it — so the dependency could not have resolved even once that was
fixed.
