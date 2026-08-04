# Code coverage for netscope.
#
#   .\scripts\coverage.ps1            # summary in the terminal
#   .\scripts\coverage.ps1 -Html      # writes target/llvm-cov/html/index.html
#
# Why a script rather than "just run cargo llvm-cov": on Windows the plain
# command fails with forty lines of rustc invocations ending in
#
#   error[E0463]: can't find crate for `profiler_builtins`
#
# which names neither the cause nor the fix. Coverage counters need the
# profiler runtime, and rustup does not ship it for `x86_64-pc-windows-gnu` —
# the default toolchain on this machine. It does ship it for MSVC. Verified:
# the gnu toolchain has zero `profiler_builtins` files under
# `lib/rustlib/x86_64-pc-windows-gnu/lib`, MSVC has two.
#
# Passing `--target x86_64-pc-windows-msvc` to the gnu toolchain does not help,
# even after `rustup target add`: cargo-llvm-cov instruments build scripts too,
# and those are built for the *host*, which is still gnu. The toolchain has to
# change, not the target.
#
# Linux and macOS need none of this; the runtime comes with the toolchain.

param(
    [switch]$Html,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'

$toolchain = ''
$targetArgs = @()

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $toolchain = '+stable-x86_64-pc-windows-msvc'

    # `rustup toolchain list` returns an array, and on an array `-notmatch`
    # filters rather than answering true/false — it returns every line that
    # does not match, which is a non-empty array and therefore truthy even when
    # the toolchain is installed. Join first so this is a string comparison.
    $installed = (rustup toolchain list) -join "`n"
    if (-not ($installed -match 'stable-x86_64-pc-windows-msvc')) {
        Write-Host "The MSVC toolchain is required for coverage on Windows and is not installed." -ForegroundColor Yellow
        Write-Host "  rustup toolchain install stable-x86_64-pc-windows-msvc"
        Write-Host "  rustup component add llvm-tools-preview --toolchain stable-x86_64-pc-windows-msvc"
        exit 1
    }
}

# The whole workspace, netscope-desktop included. It used to be excluded here,
# because its Tauri targets would not link under MSVC — a duplicate manifest
# resource, not an MSVC limitation. `desktop/src-tauri/build.rs` gives the
# archive to `-tests` now instead of every target, so nothing is doubled and
# the exclusion is gone; the comment there has the full story.
$cargoArgs = @('llvm-cov', '--workspace') + $targetArgs

if ($Html) {
    $cargoArgs += '--html'
} else {
    $cargoArgs += '--summary-only'
}
if ($OpenReport) { $cargoArgs += '--open' }

# The first run builds the whole workspace instrumented, which is slow. Say so,
# rather than leaving someone to wonder whether it has hung.
Write-Host "Running: cargo $toolchain $($cargoArgs -join ' ')" -ForegroundColor Cyan
Write-Host "The first run builds the workspace with instrumentation and takes a while." -ForegroundColor DarkGray

$env:RUST_MIN_STACK = '134217728'

if ($toolchain) {
    & cargo $toolchain @cargoArgs
} else {
    & cargo @cargoArgs
}
exit $LASTEXITCODE
