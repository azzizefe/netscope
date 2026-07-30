// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp } from './load-app.js';

const app = loadApp();

// Ethernet + IPv4 + TCP frame: 14 (eth) + 20 (ip) + 20 (tcp).
function ethIpv4Tcp() {
  const f = new Array(54).fill(0);
  // Ethernet: dst[0..6], src[6..12], type[12..14] = 0x0800
  for (let i = 0; i < 6; i++) f[i] = 0x10 + i;      // dst MAC
  for (let i = 0; i < 6; i++) f[6 + i] = 0x20 + i;  // src MAC
  f[12] = 0x08; f[13] = 0x00;                        // IPv4
  // IPv4 @14: version/IHL, proto@23, src@26..30, dst@30..34
  f[14] = 0x45;                                      // v4, IHL 5 (20 bytes)
  f[23] = 6;                                         // TCP
  f[26] = 192; f[27] = 168; f[28] = 1; f[29] = 10;   // src IP
  f[30] = 8; f[31] = 8; f[32] = 8; f[33] = 8;        // dst IP
  // TCP @34: src port @34..36 = 443, dst port @36..38 = 51000
  f[34] = 0x01; f[35] = 0xbb;                        // 443
  f[36] = 0xc7; f[37] = 0x38;                        // 51000
  return f;
}

describe('fieldRanges (Ethernet + IPv4 + TCP)', () => {
  const R = app.fieldRanges(ethIpv4Tcp());
  it('locates the Ethernet fields', () => {
    expect(R.ethDst).toEqual([0, 6]);
    expect(R.ethSrc).toEqual([6, 12]);
    expect(R.ethType).toEqual([12, 14]);
  });
  it('locates the IPv4 addresses and protocol', () => {
    expect(R.ipProto).toEqual([23, 24]);
    expect(R.ipSrc).toEqual([26, 30]);
    expect(R.ipDst).toEqual([30, 34]);
  });
  it('locates the TCP ports after the IP header', () => {
    expect(R.srcPort).toEqual([34, 36]);
    expect(R.dstPort).toEqual([36, 38]);
  });
});

describe('fieldRanges — VLAN shifts the L3 offset by 4', () => {
  it('reads the inner EtherType and IP after an 802.1Q tag', () => {
    const f = ethIpv4Tcp();
    // Insert a 4-byte VLAN tag after the MACs: type becomes 0x8100, then TCI,
    // then the real EtherType. Rebuild: splice 4 bytes at offset 12.
    f.splice(12, 0, 0x81, 0x00, 0x00, 0x0a); // 0x8100 + VID 10
    // Now bytes 12..14 = 0x8100, 14..16 = TCI, 16..18 = 0x0800 (shifted)
    const R = app.fieldRanges(f);
    expect(R.ethType).toEqual([16, 18]);
    expect(R.ipSrc).toEqual([30, 34]); // 26 + 4
    expect(R.srcPort).toEqual([38, 40]); // 34 + 4
  });
});

describe('fieldRanges — non-IP / short frames', () => {
  it('returns only Ethernet fields for a short frame', () => {
    const R = app.fieldRanges(new Array(14).fill(0));
    expect(R.ethDst).toEqual([0, 6]);
    expect(R.ipSrc).toBeUndefined();
  });
  it('returns empty for a truncated frame', () => {
    expect(app.fieldRanges([1, 2, 3])).toEqual({});
  });
});
