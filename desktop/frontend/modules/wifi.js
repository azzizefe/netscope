// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// netscope Desktop — WiFi / LAN device discovery.
//
// Two sources feed one device inventory:
//   1. Passive — every captured Ethernet frame carries the sender's real MAC in
//      bytes 6..12 and the receiver's in 0..6. Pairing those with the packet's
//      IP addresses builds a MAC↔IP↔hostname map of every neighbour that has
//      transmitted, for free, as traffic flows.
//   2. Active — an ARP sweep (backend `arp_scan`) pings every address in the
//      subnet so even silent devices answer. This fills in what passive misses.
//
// Honest limits, surfaced in the UI: this only sees the local L2 segment (the
// same WiFi/subnet), never the content of other devices' encrypted traffic, and
// per-device byte counts reflect only what we actually observe — your own
// traffic plus broadcast/multicast — not everyone's private browsing.

import { $, state, esc, els } from '../app.js';
import { macVendor, isRandomizedMac } from './oui.js';
import { fingerprintPacket, mergeIdentity, identityLabel } from './fingerprint.js';
import { invoke } from './api.js';

const BROADCAST = 'ff:ff:ff:ff:ff:ff';
const isGroupMac = (m) => !m || m === BROADCAST || m.startsWith('01:00:5e')
  || m.startsWith('33:33') || m.startsWith('01:80:c2');
const isPrivateV4 = (ip) => !!ip && (
  ip.startsWith('10.') || ip.startsWith('192.168.')
  || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  || ip.startsWith('169.254.'));

// macString(bytes, offset) — format six raw bytes as a lowercase MAC.
function macAt(raw, off) {
  if (!raw || raw.length < off + 6) return null;
  const h = (n) => raw[n].toString(16).padStart(2, '0');
  return `${h(off)}:${h(off + 1)}:${h(off + 2)}:${h(off + 3)}:${h(off + 4)}:${h(off + 5)}`;
}

/** The persistent inventory. Keyed by MAC so it survives the 10k packet-window
 *  cap in state.packets — a device seen once is never forgotten for the session. */
function devices() {
  if (!state.devices) state.devices = new Map();
  return state.devices;
}

function touch(mac) {
  const d = devices();
  let dev = d.get(mac);
  if (!dev) {
    dev = {
      mac,
      vendor: macVendor(mac),
      randomized: isRandomizedMac(mac),
      ips: new Set(),
      hostname: null,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      packets: 0,
      bytes: 0,
      protocols: new Map(),
      identity: null,
      viaScan: false,
    };
    d.set(mac, dev);
  }
  return dev;
}

/** Fold one packet into the inventory. Called from ingestPacket, so it must be
 *  cheap: a couple of slice reads and map bumps, no allocation in the common
 *  path. */
export function observeDevice(pkt) {
  const raw = pkt.raw;
  if (!raw || raw.length < 14) return;
  const srcMac = macAt(raw, 6);
  const dstMac = macAt(raw, 0);

  if (srcMac && !isGroupMac(srcMac)) {
    const dev = touch(srcMac);
    dev.lastSeen = Date.now();
    dev.packets++;
    dev.bytes += pkt.length || 0;
    if (pkt.protocol) dev.protocols.set(pkt.protocol, (dev.protocols.get(pkt.protocol) || 0) + 1);
    if (isPrivateV4(pkt.src_addr)) dev.ips.add(pkt.src_addr);
    if (pkt.src_host && !dev.hostname) dev.hostname = pkt.src_host;
    // The transmitter is the device we can fingerprint: its mDNS/NBNS/DHCP
    // broadcasts and its packets' TTL all describe it.
    const fp = fingerprintPacket(pkt);
    if (fp.name || fp.deviceType || fp.os || fp.model) dev.identity = mergeIdentity(dev.identity, fp);
  }
  // The receiver's MAC + IP is a valid mapping too (its own traffic may not have
  // been captured yet), but don't credit it with the sender's bytes/protocol.
  if (dstMac && !isGroupMac(dstMac)) {
    const dev = touch(dstMac);
    if (isPrivateV4(pkt.dst_addr)) dev.ips.add(pkt.dst_addr);
    if (pkt.dst_host && !dev.hostname) dev.hostname = pkt.dst_host;
  }
}

/** Merge an ARP-scan result [{ip, mac}] into the inventory. */
function mergeScan(results) {
  for (const { ip, mac } of results) {
    if (!mac || isGroupMac(mac)) continue;
    const dev = touch(mac);
    dev.viaScan = true;
    if (ip) dev.ips.add(ip);
  }
}

let scanning = false;

async function runScan() {
  if (scanning) return;
  scanning = true;
  const btn = $('#wifi-scan');
  const iface = els.interfaceSelect ? els.interfaceSelect.value : '__all__';
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Taranıyor…'; }
  try {
    const results = await invoke('arp_scan', { interface: iface });
    mergeScan(results || []);
    renderWifi();
    setStatus(`${(results || []).length} cihaz yanıtladı.`);
  } catch (e) {
    setStatus(`Tarama başarısız: ${e}`, true);
  } finally {
    scanning = false;
    if (btn) { btn.disabled = false; btn.textContent = '📡 Ağı tara (ARP)'; }
  }
}

function setStatus(text, isErr) {
  const el = $('#wifi-status');
  if (el) { el.textContent = text; el.classList.toggle('wifi-err', !!isErr); }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function fmtAge(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s önce`;
  if (s < 3600) return `${Math.round(s / 60)}dk önce`;
  return `${Math.round(s / 3600)}sa önce`;
}

// A glyph for a device type/OS so the list is scannable at a glance.
function deviceIcon(id) {
  const t = (id && id.deviceType) || '';
  const os = (id && id.os) || '';
  if (/iPhone|Android telefon/i.test(t)) return '📱';
  if (/iPad/i.test(t)) return '📱';
  if (/MacBook|Mac\b|iMac|Mac mini|Mac Pro/i.test(t)) return '💻';
  if (/Apple Watch/i.test(t)) return '⌚';
  if (/HomePod|Sonos|AirPlay|Spotify|hoparlör|Alexa/i.test(t)) return '🔊';
  if (/Apple TV|Chromecast|Android TV|Roku|Google TV|Fire/i.test(t)) return '📺';
  if (/Yazıcı|Tarayıcı/i.test(t)) return '🖨';
  if (/HomeKit|Hue|IoT/i.test(t)) return '💡';
  if (/NAS|Dosya sunucusu/i.test(t)) return '🗄';
  if (/router|Ağ cihazı/i.test(t) || /router/i.test(os)) return '🛜';
  if (/workstation|Bilgisayar/i.test(t)) return '🖥';
  if (/Windows/i.test(os)) return '🖥';
  if (/Apple|Linux|Android/i.test(os)) return '💻';
  return '❔';
}

export function renderWifi() {
  const host = $('#wifi-list');
  if (!host) return;
  const list = [...devices().values()];
  const summary = $('#wifi-summary');
  if (summary) {
    const withIp = list.filter((d) => d.ips.size).length;
    summary.textContent = list.length
      ? `${list.length} cihaz görüldü · ${withIp} tanesi IP ile eşleşti`
      : 'Henüz cihaz yok — yakalama başlatın ya da “Ağı tara”ya basın.';
  }
  if (!list.length) {
    host.innerHTML = `<div class="wifi-empty">Aynı WiFi/LAN üzerindeki cihazlar, trafik aktıkça ya da
      ağ taramasıyla burada listelenir. Yalnızca kendi ağınızdaki cihazlar görünür.</div>`;
    return;
  }
  // Most-recently-active first; scan-only (silent) devices sort by IP after.
  list.sort((a, b) => (b.packets - a.packets) || (b.lastSeen - a.lastSeen));

  const rows = list.map((d) => {
    const ip = [...d.ips].sort()[0] || '—';
    const extraIps = d.ips.size > 1 ? ` +${d.ips.size - 1}` : '';
    const vendor = d.vendor || (d.randomized ? 'Rastgele MAC' : '—');
    const topProto = [...d.protocols.entries()].sort((a, b) => b[1] - a[1])[0];
    const proto = topProto ? topProto[0] : (d.viaScan ? 'sessiz' : '—');
    const seen = d.packets ? fmtAge(d.lastSeen) : (d.viaScan ? 'tarama' : '—');
    const tag = d.viaScan && !d.packets ? '<span class="wifi-tag wifi-tag-scan">tarama</span>' : '';
    const rnd = d.randomized ? '<span class="wifi-tag wifi-tag-rnd" title="Rastgele/geçici MAC">🎲</span>' : '';

    // The "device" cell is the headline: an icon, the best type/name guess, and
    // the exact model when mDNS gave us one.
    const id = d.identity;
    const label = identityLabel(id);
    const name = (id && id.name) || d.hostname;
    const icon = deviceIcon(id);
    let devCell;
    if (label || name) {
      const main = esc(name || label);
      const sub = name && label && label !== name ? `<span class="wifi-dim"> · ${esc(label)}</span>` : '';
      const model = id && id.model ? `<span class="wifi-dim" title="mDNS model"> (${esc(id.model)})</span>` : '';
      devCell = `<span class="wifi-dev-icon">${icon}</span> ${main}${sub}${model}`;
    } else {
      devCell = `<span class="wifi-dev-icon">${icon}</span> <span class="wifi-dim">bilinmiyor</span>`;
    }
    const os = id && id.os ? esc(id.os) : '—';

    return `<tr>
      <td class="wifi-dev">${devCell} ${tag}</td>
      <td class="wifi-os">${os}</td>
      <td class="mono">${esc(ip)}${extraIps ? `<span class="wifi-dim">${esc(extraIps)}</span>` : ''}</td>
      <td class="wifi-mac mono">${esc(d.mac)} ${rnd}</td>
      <td class="wifi-vendor wifi-dim">${esc(vendor)}</td>
      <td class="wifi-proto">${esc(proto)}</td>
      <td class="wifi-num">${d.packets || '—'}</td>
      <td class="wifi-num">${d.bytes ? fmtBytes(d.bytes) : '—'}</td>
      <td class="wifi-dim">${esc(seen)}</td>
    </tr>`;
  }).join('');

  host.innerHTML = `<table class="wifi-table">
    <thead><tr>
      <th>Cihaz</th><th>İşletim sistemi</th><th>IP</th><th>MAC adresi</th><th>Üretici (çip)</th>
      <th>Baskın protokol</th><th>Paket</th><th>Trafik</th><th>Son görülme</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

let wired = false;
export function initWifi() {
  if (wired) return;
  wired = true;
  const btn = $('#wifi-scan');
  if (btn) btn.addEventListener('click', runScan);
  const clr = $('#wifi-clear');
  if (clr) clr.addEventListener('click', () => { devices().clear(); renderWifi(); setStatus(''); });
}
