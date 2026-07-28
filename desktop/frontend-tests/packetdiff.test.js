// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp } from './load-app.js';

const app = loadApp();

/** Ethernet + IPv4 + TCP frame, with every field the comparison reads. */
function frame({ srcMac = 0x10, dstMac = 0x20, srcPort = 443, dstPort = 51000 } = {}) {
  const f = new Array(54).fill(0);
  for (let i = 0; i < 6; i++) f[i] = dstMac + i;
  for (let i = 0; i < 6; i++) f[6 + i] = srcMac + i;
  f[12] = 0x08; f[13] = 0x00;
  f[14] = 0x45;
  f[23] = 6;
  f[26] = 192; f[27] = 168; f[28] = 1; f[29] = 10;
  f[30] = 8; f[31] = 8; f[32] = 8; f[33] = 8;
  f[34] = (srcPort >> 8) & 0xff; f[35] = srcPort & 0xff;
  f[36] = (dstPort >> 8) & 0xff; f[37] = dstPort & 0xff;
  return f;
}

function packet(overrides = {}) {
  return {
    raw: frame(),
    length: 54,
    protocol: 'TCP',
    summary: 'TCP segment',
    src_addr: '192.168.1.10',
    dst_addr: '8.8.8.8',
    src_port: 443,
    dst_port: 51000,
    ...overrides,
  };
}

describe('packetHeaderFields', () => {
  it('flattens the decoded header into ordered, comparable fields', () => {
    const fields = app.packetHeaderFields(packet());
    const sections = [...new Set(fields.map((f) => f.section))];

    // Wire order: the comparison shows layers as they sit on the wire, so a
    // missing layer keeps its place rather than shuffling the rows below it.
    // The transport layer's *name* comes from a table the backend fills in at
    // startup and which is empty here, but its ports must still be reported —
    // that is what the last section checks.
    expect(sections).toEqual(['Frame', 'Ethernet', 'Network', 'Transport']);

    const find = (section, key) =>
      fields.find((f) => f.section === section && f.key === key)?.value;
    expect(find('Network', 'Source address')).toBe('192.168.1.10');
    expect(find('Transport', 'Destination port')).toBe('51000');
    expect(find('Ethernet', 'EtherType')).toBe('0x0800');
  });

  it('omits fields the packet does not have rather than inventing them', () => {
    const fields = app.packetHeaderFields(packet({ src_port: null, dst_port: null, raw: [] }));
    expect(fields.some((f) => f.section === 'Ethernet')).toBe(false);
    expect(fields.some((f) => f.key === 'Source port')).toBe(false);
    // The frame layer is always answerable, so it must still be there.
    expect(fields.some((f) => f.section === 'Frame')).toBe(true);
  });
});

describe('renderPacketDiff', () => {
  const withPackets = (pktA, pktB) => app.renderPacketDiff(pktA, pktB);

  it('asks for two packets before it compares anything', () => {
    const html = withPackets(null, null);
    expect(html).toContain('Packet A');
    expect(html).not.toContain('diff-changed');
  });

  it('reports identical packets as identical', () => {
    const html = withPackets(packet(), packet());
    expect(html).toContain('identical across every field');
    expect(html).not.toContain('diff-changed');
  });

  /// The whole point of the view: two rows that look alike in the list, and
  /// exactly which field separates them.
  it('marks only the fields that actually differ', () => {
    const html = withPackets(packet(), packet({ dst_port: 8080 }));
    expect(html).toContain('1 field differs');

    const changed = html.split('<tr').filter((row) => row.includes('diff-changed'));
    expect(changed).toHaveLength(1);
    expect(changed[0]).toContain('Destination port');
  });

  it('counts several differences separately', () => {
    const html = withPackets(
      packet(),
      packet({ dst_port: 8080, src_addr: '10.0.0.1', protocol: 'HTTP' }),
    );
    expect(html).toMatch(/\d+ fields differ/);
    const changed = html.split('<tr').filter((row) => row.includes('diff-changed'));
    expect(changed.length).toBeGreaterThanOrEqual(3);
  });

  /// A field only one side has is the interesting case — the row has to exist
  /// so the absence is visible, rather than the field vanishing from the table.
  it('keeps a row for a field only one packet carries', () => {
    const html = withPackets(packet(), packet({ src_port: null, dst_port: null }));
    expect(html).toContain('diff-absent');
    expect(html).toContain('Source port');
  });

  /// Excel-style: the old value is marked red and the new one green, on the
  /// cells rather than the row, so "changed" reads differently from "appeared".
  it('marks the old value red and the new value green', () => {
    const html = withPackets(packet(), packet({ dst_port: 8080 }));
    const row = html.split('<tr').find((r) => r.includes('diff-changed'));

    expect(row).toContain('diffcell-old');
    expect(row).toContain('diffcell-new');
    // The colours have to land on the right side of the row.
    expect(row.indexOf('diffcell-old')).toBeLessThan(row.indexOf('diffcell-new'));
    expect(row.indexOf('51000')).toBeLessThan(row.indexOf('8080'));
  });

  /// A field only one packet has gets exactly one coloured cell — the other
  /// side is marked missing, not marked as a value that changed.
  it('colours one side only when a field is absent from the other', () => {
    const html = withPackets(packet(), packet({ src_port: null, dst_port: null }));
    const row = html.split('<tr').find((r) => r.includes('Source port'));

    expect(row).toContain('diff-missing');
    expect(row).not.toContain('diffcell-new');
  });

  /// Identical rows carry no colour at all. If every row were tinted the view
  /// would be a wall again and the differences would stop standing out.
  it('leaves identical fields uncoloured', () => {
    const html = withPackets(packet(), packet());
    expect(html).not.toContain('diffcell-old');
    expect(html).not.toContain('diffcell-new');
  });
});
