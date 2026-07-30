<#
.SYNOPSIS
    Builds the WASM display-filter module the desktop frontend loads at runtime.

.DESCRIPTION
    `desktop/frontend/wasm/` is a build output, so it is not committed. The
    desktop frontend and the vitest suite both load it directly
    (see desktop/frontend-tests/load-app.js), which means a fresh clone cannot
    run `npm test` until this script has been run once.

    The wasm-bindgen CLI version must match the `wasm-bindgen` crate version in
    Cargo.lock exactly, or the generated glue fails to load with a version
    mismatch error -- hence the pin below.
#>
param(
    [string]$BindgenVersion = "0.2.126"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot

try {
    Write-Host "-> Ensuring wasm32-unknown-unknown target ..."
    rustup target add wasm32-unknown-unknown | Out-Null

    Write-Host "-> Building netscope-wasm (release) ..."
    cargo build -p netscope-wasm --release --target wasm32-unknown-unknown
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    $installed = (cargo install --list) -match "^wasm-bindgen-cli v$([regex]::Escape($BindgenVersion))"
    if (-not $installed) {
        Write-Host "-> Installing wasm-bindgen-cli $BindgenVersion (this takes a few minutes) ..."
        cargo install wasm-bindgen-cli --version $BindgenVersion --force
        if ($LASTEXITCODE -ne 0) { throw "cargo install wasm-bindgen-cli failed" }
    } else {
        Write-Host "[ok] wasm-bindgen-cli $BindgenVersion already installed"
    }

    Write-Host "-> Generating JS bindings into desktop/frontend/wasm ..."
    wasm-bindgen --target web `
        --out-dir desktop/frontend/wasm `
        target/wasm32-unknown-unknown/release/netscope_wasm.wasm
    if ($LASTEXITCODE -ne 0) { throw "wasm-bindgen failed" }

    Write-Host "[ok] WASM module ready -- 'cd desktop/frontend-tests; npm test' will now run"
} finally {
    Pop-Location
}
