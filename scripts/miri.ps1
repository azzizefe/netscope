# Miri — Memory safety verification for netscope-core.
#
#   .\scripts\miri.ps1
#
# Runs Miri on the subset of tests that contain only pure in-memory logic
# (dissectors, filters, models, protocol parsing). Tests that touch the
# filesystem, network sockets, or spawn subprocesses are excluded because
# Miri is an interpreter — it cannot execute real OS syscalls like
# CreateDirectoryW, CreateFileW, GetFileAttributesW, bind/connect, or
# CreateProcessW.
#
# Those OS-dependent tests are already covered by normal `cargo test`, which
# runs them natively. Miri's value is catching undefined behaviour in the
# *parsing* code — the code that handles attacker-controlled bytes.
#
# Requires:
#   rustup component add --toolchain nightly-x86_64-pc-windows-msvc miri

param(
    [string]$Filter = ""
)

$ErrorActionPreference = 'Stop'

$env:MIRIFLAGS = "-Zmiri-disable-isolation"

# Modules whose tests are pure in-memory logic and safe to run under Miri.
# Each entry is a test name filter passed to `-- <filter>`.
$safeModules = @(
    "dissectors::",
    "filter::",
    "models::",
    "flows::",
    "ai_traffic::",
    "alerting::",
    "analyst_command_center::",
    "stats::",
    "stream::",
    "names::",
    "pair_correlation::"
)

if ($Filter) {
    $safeModules = @($Filter)
}

$failed = 0
$passed = 0

foreach ($mod in $safeModules) {
    Write-Host "`nRunning Miri: $mod" -ForegroundColor Cyan
    cargo +nightly miri test -p netscope-core --lib -- $mod 2>&1 | ForEach-Object {
        Write-Host $_
    }
    if ($LASTEXITCODE -eq 0) {
        $passed++
    } else {
        $failed++
        Write-Host "FAILED: $mod" -ForegroundColor Red
    }
}

Write-Host "`n--- Miri Summary ---" -ForegroundColor Yellow
Write-Host "Passed: $passed / $($safeModules.Count)" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
if ($failed -gt 0) {
    Write-Host "Failed: $failed" -ForegroundColor Red
    exit 1
}
