// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// Load the real, shipped frontend source (../frontend/app.js) inside a Node vm
// sandbox and expose its top-level functions for unit testing — no duplication,
// no build step, and no changes to the shipped app.
//
// app.js is a plain browser script (not an ES module): its top-level `function`
// declarations attach to the sandbox global, so we can pull them straight off
// the context after evaluation. The DOM / Tauri globals it touches at load time
// are stubbed just enough that evaluation succeeds; the pure analysis functions
// under test never reach into them.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TextDecoder, TextEncoder } from 'node:util';
import path from 'node:path';
import vm from 'node:vm';

const here = path.dirname(fileURLToPath(import.meta.url));
const filterSource = readFileSync(path.join(here, '..', 'frontend', 'filter.js'), 'utf8');

function stripESM(src) {
  return src
    .replace(/import\s+(?:{[\s\S]*?}|[a-zA-Z0-9_*]+)\s+from\s+['"].*?['"];?/g, '')
    .replace(/export\s+(function|const|let|class|async\s+function)\b/g, '$1')
    .replace(/export\s+{[\s\S]*?};?/g, '')
    .replace(/export\s+default\s+.*?;?/g, '')
    .replace(/\bimport\.meta\.url\b/g, '""')
    .replace(/\bimport\.meta\b/g, '{}');
}

function loadModule(name) {
  try {
    return readFileSync(path.join(here, '..', 'frontend', name), 'utf8');
  } catch {
    return '';
  }
}

function initWasmInContext(ctx) {
  const wasmJsSource = readFileSync(path.join(here, '..', 'frontend', 'wasm', 'netscope_wasm.js'), 'utf8');
  const wasmBuffer = readFileSync(path.join(here, '..', 'frontend', 'wasm', 'netscope_wasm_bg.wasm'));
  vm.runInContext(stripESM(wasmJsSource), ctx, { filename: 'netscope_wasm.js' });
  ctx.wasmBuffer = wasmBuffer;
  ctx.initSync(vm.runInContext("({ module: wasmBuffer })", ctx));
  delete ctx.wasmBuffer;
}

export function loadApp() {
  const noop = () => {};
  const stubEl = () => ({
    style: { setProperty: noop }, dataset: {}, value: '', textContent: '', innerHTML: '',
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    addEventListener: noop, appendChild: noop, remove: noop, focus: noop, select: noop,
    setAttribute: noop, getAttribute: () => null, querySelector: () => null, querySelectorAll: () => [],
  });
  const document = {
    addEventListener: noop, createElement: () => stubEl(), body: stubEl(),
    documentElement: stubEl(), querySelector: () => null, querySelectorAll: () => [],
  };

  const ctx = {
    console,
    navigator: { language: 'en', clipboard: null },
    localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
    performance: { now: () => 0 },
    document,
    setTimeout: noop, clearTimeout: noop, setInterval: () => 0, clearInterval: noop,
    fetch: () => Promise.reject(new Error('network disabled in tests')),
    I18N: { t: (k) => k, apply: noop, lang: () => 'en', has: () => true },
    TextDecoder,
    TextEncoder,
  };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;

  vm.createContext(ctx);
  initWasmInContext(ctx);
  // filter.js must run first: app.js references the NetscopeFilter global it
  // defines (exactly as index.html loads them in order).
  vm.runInContext(stripESM(filterSource), ctx, { filename: 'filter.js' });
  const apiSource = loadModule('modules/api.js');
  const packetsSource = loadModule('modules/views/packets.js');
  const voipSource = loadModule('modules/views/voip.js');
  const appSource = readFileSync(path.join(here, '..', 'frontend', 'app.js'), 'utf8');

  if (apiSource) vm.runInContext(stripESM(apiSource), ctx, { filename: 'api.js' });
  if (packetsSource) vm.runInContext(stripESM(packetsSource), ctx, { filename: 'packets.js' });
  if (voipSource) vm.runInContext(stripESM(voipSource), ctx, { filename: 'voip.js' });
  vm.runInContext(stripESM(appSource), ctx, { filename: 'app.js' });
  return ctx;
}

/** Load just filter.js (no DOM/app needed) and return its NetscopeFilter. */
export function loadFilter() {
  const ctx = { console, TextDecoder, TextEncoder };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  initWasmInContext(ctx);
  vm.runInContext(stripESM(filterSource), ctx, { filename: 'filter.js' });
  return ctx.NetscopeFilter;
}

// ---- Test packet builders (raw Ethernet frames as byte arrays) ----

/** Ethernet + IPv4 + TCP frame with an application payload. */
export function tcpFrame(payloadBytes, { srcPort = 12345, dstPort = 80 } = {}) {
  const eth = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00]; // dst,src,ethertype IPv4
  const ip = new Array(20).fill(0);
  ip[0] = 0x45;           // version 4, IHL 5 (20 bytes)
  ip[9] = 6;              // protocol TCP
  const tcp = new Array(20).fill(0);
  tcp[0] = srcPort >> 8; tcp[1] = srcPort & 0xff;
  tcp[2] = dstPort >> 8; tcp[3] = dstPort & 0xff;
  tcp[12] = 0x50;         // data offset 5 (20 bytes)
  return eth.concat(ip, tcp, [...payloadBytes]);
}

/** Ethernet + IPv4 + UDP frame with an application payload. */
export function udpFrame(payloadBytes, { srcPort = 5353, dstPort = 5353 } = {}) {
  const eth = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
  const ip = new Array(20).fill(0);
  ip[0] = 0x45; ip[9] = 17; // UDP
  const udp = new Array(8).fill(0);
  udp[0] = srcPort >> 8; udp[1] = srcPort & 0xff;
  udp[2] = dstPort >> 8; udp[3] = dstPort & 0xff;
  return eth.concat(ip, udp, [...payloadBytes]);
}

/** ASCII string → array of byte values. */
export function bytes(str) {
  return [...str].map((c) => c.charCodeAt(0) & 0xff);
}
