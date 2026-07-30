#!/usr/bin/env bash
# Builds the WASM display-filter module the desktop frontend loads at runtime.
#
# `desktop/frontend/wasm/` is a build output, so it is not committed. The
# desktop frontend and the vitest suite both load it directly (see
# desktop/frontend-tests/load-app.js), which means a fresh clone cannot run
# `npm test` until this script has been run once.
#
# The wasm-bindgen CLI version must match the `wasm-bindgen` crate version in
# Cargo.lock exactly, or the generated glue fails to load with a version
# mismatch error — hence the pin below.
set -euo pipefail

BINDGEN_VERSION="${BINDGEN_VERSION:-0.2.126}"
cd "$(dirname "$0")/.."

echo "→ Ensuring wasm32-unknown-unknown target ..."
rustup target add wasm32-unknown-unknown >/dev/null

echo "→ Building netscope-wasm (release) ..."
cargo build -p netscope-wasm --release --target wasm32-unknown-unknown

if cargo install --list | grep -q "^wasm-bindgen-cli v${BINDGEN_VERSION}"; then
  echo "✓ wasm-bindgen-cli ${BINDGEN_VERSION} already installed"
else
  echo "→ Installing wasm-bindgen-cli ${BINDGEN_VERSION} (this takes a few minutes) ..."
  cargo install wasm-bindgen-cli --version "${BINDGEN_VERSION}" --force
fi

echo "→ Generating JS bindings into desktop/frontend/wasm ..."
wasm-bindgen --target web \
  --out-dir desktop/frontend/wasm \
  target/wasm32-unknown-unknown/release/netscope_wasm.wasm

echo "✓ WASM module ready — 'cd desktop/frontend-tests && npm test' will now run"
