// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// netscope Desktop — passive device fingerprinting.
//
// A MAC's OUI only names the network-chip maker, and modern phones randomise
// their MAC, so it often says nothing. This module works out WHAT a device is —
// "iPhone", "MacBook", "Android TV", "printer", "Windows PC" — from signals the
// device broadcasts anyway:
//
//   • mDNS/Bonjour (UDP 5353) — Apple publishes `model=` (exact hardware code)
//     and everyone advertises service types (_airplay, _googlecast, _printer…)
//     that name the device category, plus a "Name.local" hostname.
//   • NetBIOS name service (UDP 137) — a Windows machine's own name.
//   • DHCP (UDP 67/68) — the hostname (option 12) and vendor class (option 60,
//     e.g. "android-dhcp-14", "MSFT 5.0") that identify the OS.
//   • IP TTL — the initial value gives the OS family (Windows 128, Apple/Linux/
//     Android 64, network gear 255).
//
// It reads the bytes the capture already delivers, so there is no extra probe
// and nothing leaves the machine. Every result is a best-effort guess, labelled
// as such — a randomised MAC with no broadcasts stays "unknown".

// Interpret raw bytes (array of 0..255) as a Latin-1 string so ASCII markers in
// the payload (service names, model=, hostnames) can be matched directly. Cap
// the length so a jumbo frame can't turn each packet into a big allocation.
function asAscii(raw, max = 900) {
  const n = Math.min(raw.length, max);
  let s = '';
  for (let i = 0; i < n; i++) {
    const b = raw[i];
    s += (b >= 32 && b < 127) ? String.fromCharCode(b) : '\n';
  }
  return s;
}

// mDNS service type → human device category. First match wins, so order from
// most specific to least.
const SERVICE_TYPES = [
  [/_androidtvremote/i, 'Android TV'],
  [/_googlecast\b/i, 'Chromecast / Google TV'],
  [/_googlezone|_google/i, 'Google cihazı'],
  [/_airplay\b|_raop\b/i, 'Apple AirPlay (TV/hoparlör)'],
  [/_companion-link|_apple-mobdev|_rdlink|_sleep-proxy/i, 'Apple cihazı'],
  [/_homekit|_hap\b/i, 'HomeKit cihazı'],
  [/_sonos\b/i, 'Sonos hoparlör'],
  [/_roku/i, 'Roku'],
  [/_amzn|_alexa/i, 'Amazon (Alexa/Fire)'],
  [/_spotify-connect/i, 'Spotify Connect cihazı'],
  [/_nvstream/i, 'NVIDIA Shield / oyun PC’si'],
  [/_hue\b|_philips/i, 'Philips Hue'],
  [/_miio|_xiaomi/i, 'Xiaomi IoT'],
  [/_ipps?\b|_printer\b|_pdl-datastream|_ipp\b/i, 'Yazıcı'],
  [/_uscan|_scanner\b/i, 'Tarayıcı'],
  [/_smb\b|_afpovertcp/i, 'Dosya sunucusu / NAS'],
  [/_workstation\b/i, 'Bilgisayar (workstation)'],
];

// Apple hardware-model prefix (from mDNS `model=`) → product family.
const APPLE_MODEL = [
  [/^iPhone/i, 'iPhone'],
  [/^iPad/i, 'iPad'],
  [/^Watch/i, 'Apple Watch'],
  [/^AudioAccessory/i, 'HomePod'],
  [/^AppleTV/i, 'Apple TV'],
  [/^MacBookPro/i, 'MacBook Pro'],
  [/^MacBookAir/i, 'MacBook Air'],
  [/^MacBook/i, 'MacBook'],
  [/^Macmini/i, 'Mac mini'],
  [/^iMac/i, 'iMac'],
  [/^MacPro/i, 'Mac Pro'],
  [/^(RackMac|Mac\d)/i, 'Mac'],
];

// Decode the first RFC 1001 first-level-encoded NetBIOS name in a frame. The
// name sits after a 0x20 length byte as 32 chars each in 'A'..'P'; pairs decode
// to one byte. Returns the trimmed machine name (the 16th byte is a type code,
// dropped) or null.
function decodeNetbiosName(raw) {
  for (let i = 0; i + 33 <= raw.length; i++) {
    if (raw[i] !== 0x20) continue;
    let ok = true;
    for (let j = 1; j <= 32; j++) {
      if (raw[i + j] < 0x41 || raw[i + j] > 0x50) { ok = false; break; }
    }
    if (!ok) continue;
    let name = '';
    for (let j = 0; j < 16; j++) {
      const hi = raw[i + 1 + j * 2] - 0x41;
      const lo = raw[i + 2 + j * 2] - 0x41;
      name += String.fromCharCode((hi << 4) | lo);
    }
    name = name.slice(0, 15).replace(/[\x00- ]+$/, '');
    if (name && /[\x20-\x7e]/.test(name) && !/[\x00-\x1f]/.test(name)) return name;
  }
  return null;
}

/** Pull a device fingerprint out of one packet. Returns a partial
 *  {name, deviceType, os, model, vendorHint} — any field may be absent. Cheap
 *  for the common case: only mDNS/NBNS/DHCP get the ASCII scan; everything else
 *  just reads the TTL byte. */
export function fingerprintPacket(pkt) {
  const out = {};
  const raw = pkt.raw;
  if (!raw || raw.length < 15) return out;

  // OS family from the IP TTL / hop limit. EtherType at 12..14 picks v4 vs v6;
  // skip a single VLAN tag if present.
  let et = (raw[12] << 8) | raw[13];
  let l3 = 14;
  if (et === 0x8100 && raw.length > 18) { et = (raw[16] << 8) | raw[17]; l3 = 18; }
  let ttl = null;
  if (et === 0x0800 && raw.length > l3 + 8) ttl = raw[l3 + 8];       // IPv4 TTL
  else if (et === 0x86dd && raw.length > l3 + 7) ttl = raw[l3 + 7];  // IPv6 hop limit
  if (ttl != null) {
    if (ttl > 64 && ttl <= 128) out.os = 'Windows';
    else if (ttl > 0 && ttl <= 64) out.os = 'Apple / Linux / Android';
    else if (ttl > 128) out.os = 'Ağ cihazı / router';
  }

  const proto = pkt.protocol;
  if (proto !== 'mDNS' && proto !== 'NBNS' && proto !== 'DHCP') return out;
  const text = asAscii(raw);

  if (proto === 'mDNS') {
    // model=<code> is published in the _device-info TXT record as plain ASCII.
    const m = text.match(/model=([A-Za-z0-9,]+)/);
    if (m) {
      out.model = m[1];
      const fam = APPLE_MODEL.find(([re]) => re.test(m[1]));
      if (fam) out.deviceType = fam[1];
    }
    if (!out.deviceType) {
      const svc = SERVICE_TYPES.find(([re]) => re.test(text));
      if (svc) out.deviceType = svc[1];
    }
    // The advertised "<Name>.local" — the device's own chosen name.
    const host = text.match(/([A-Za-z0-9][A-Za-z0-9 _-]{1,40})\.local/);
    if (host) out.name = host[1].replace(/[ _]+$/, '');
  } else if (proto === 'NBNS') {
    // NetBIOS names are first-level encoded on the wire (RFC 1001): each real
    // byte becomes two chars in 'A'..'P', one per nibble. A plain-ASCII scan
    // would only see the gibberish, so decode the 32-char run properly.
    // Just the name — NetBIOS is answered by Samba and many routers too, so it
    // is not proof of Windows. The OS is left to the more reliable TTL/DHCP.
    const nb = decodeNetbiosName(raw);
    if (nb) out.name = nb;
  } else if (proto === 'DHCP') {
    if (/android-dhcp-?(\d+)?/i.test(text)) {
      const v = text.match(/android-dhcp-?(\d+)/i);
      out.deviceType = 'Android telefon/tablet';
      out.os = v ? `Android ${v[1]}` : 'Android';
    } else if (/MSFT 5\.0|MSFT\b/i.test(text)) {
      out.os = 'Windows';
    } else if (/\bdhcpcd\b|\budhcp\b/i.test(text)) {
      out.os = out.os || 'Linux / gömülü';
    }
  }
  return out;
}

/** Fold a fresh fingerprint into a device's accumulated identity, keeping the
 *  strongest signal seen so far. Mutates and returns `id`. */
export function mergeIdentity(id, fp) {
  id = id || { name: null, deviceType: null, os: null, model: null };
  // A concrete model/type always wins; never downgrade to a weaker guess.
  if (fp.deviceType && (!id.deviceType || id._weakType)) {
    id.deviceType = fp.deviceType;
    id._weakType = false;
  }
  if (fp.model && !id.model) id.model = fp.model;
  if (fp.os && (!id.os || id._weakOs)) { id.os = fp.os; id._weakOs = false; }
  // Prefer an mDNS/NBNS self-name; don't overwrite one we already have.
  if (fp.name && !id.name) id.name = fp.name;
  return id;
}

/** Best one-line label for a device's identity, or null if we truly don't know.
 *  Combines the device type with the OS when they add information. */
export function identityLabel(id) {
  if (!id) return null;
  const type = id.deviceType;
  const os = id.os;
  if (type && os && !type.toLowerCase().includes(os.split(' ')[0].toLowerCase())) {
    return `${type}`;         // type is already specific; OS shown separately
  }
  return type || os || null;
}
