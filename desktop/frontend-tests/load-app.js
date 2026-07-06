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
import path from 'node:path';
import vm from 'node:vm';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(here, '..', 'frontend', 'app.js'), 'utf8');

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
  };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;

  vm.createContext(ctx);
  vm.runInContext(source, ctx, { filename: 'app.js' });
  return ctx;
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
