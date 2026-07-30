// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
// Virtual scrolling of the packet list (ROADMAP §2.2): only the viewport
// window is materialised in the DOM, a spacer carries the full list height,
// and scrolling re-renders the window at the new position.

import { describe, it, expect } from 'vitest';
import { loadApp } from './load-app.js';

const noop = () => {};
const fakeEl = () => ({
  style: {},
  classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
  innerHTML: '',
  scrollTop: 0,
  clientHeight: 600,
  scrollHeight: 0,
  offsetHeight: 33,
});

function appWithPackets(count) {
  const ctx = loadApp();
  const { state, els } = ctx.__netscopeTest;
  ctx.state = state;
  const table = fakeEl();
  const list = fakeEl();
  Object.assign(els, {
    packetTable: table,
    packetList: list,
    packetHeader: { offsetHeight: 33 },
    filterInput: fakeEl(),
  });
  for (let i = 0; i < count; i++) {
    state.packets.push({
      timestamp: '12:00:00.000',
      epoch_ms: 1700000000000 + i,
      src_addr: '10.0.0.1',
      dst_addr: '10.0.0.2',
      src_port: 1000,
      dst_port: 80,
      protocol: 'TCP',
      length: 60,
      summary: `packet number ${i}`,
      raw: [],
    });
  }
  return { ctx, table, list };
}

describe('virtual packet list', () => {
  it('materialises only the viewport window, with a full-height spacer', () => {
    const { ctx, list } = appWithPackets(5000);
    ctx.renderPacketList();

    // Spacer height = every row, at the fixed row height.
    expect(list.style.height).toBe(`${5000 * 24}px`);

    // DOM rows = viewport (600px / 24px = 25) + overscan, nowhere near 5000.
    const rows = (list.innerHTML.match(/class="packet-row/g) || []).length;
    expect(rows).toBeGreaterThanOrEqual(25);
    expect(rows).toBeLessThan(120);
  });

  it('renders the window at the scroll position', () => {
    const { ctx, table, list } = appWithPackets(5000);
    ctx.renderPacketList();

    table.scrollTop = 2500 * 24; // jump deep into the list
    table.scrollHeight = 5000 * 24;
    ctx.renderPacketRows();

    expect(list.innerHTML).toContain('data-index="2500"');
    expect(list.innerHTML).toContain('packet number 2500');
    expect(list.innerHTML).not.toContain('data-index="0"');
    expect(list.innerHTML).not.toContain('data-index="4999"');
  });

  it('keeps absolute indices so row clicks map to filteredPackets', () => {
    const { ctx, table, list } = appWithPackets(200);
    ctx.renderPacketList();
    table.scrollHeight = 200 * 24;
    table.scrollTop = 100 * 24;
    ctx.renderPacketRows();

    const m = list.innerHTML.match(/data-index="(\d+)"/);
    const first = parseInt(m[1], 10);
    expect(ctx.state.filteredPackets[first].summary).toBe(`packet number ${first}`);
  });

  it('shows the empty state without a spacer', () => {
    const { ctx, list } = appWithPackets(0);
    ctx.renderPacketList();
    expect(list.style.height).toBe('auto');
    expect(list.innerHTML).toContain('packets-empty');
  });

  // The pane is the first thing a new user sees and it is the largest thing on
  // screen. It has to say what to do next, and it has to do so in the language
  // the rest of the window is in — it was hardcoded English while the chrome
  // around it translated.
  it('the empty state is translated and tells the user what to do', () => {
    const { ctx, list } = appWithPackets(0);
    ctx.renderPacketList();
    const html = list.innerHTML;
    expect(html).toContain('empty-title');
    expect(html).toContain('empty-body');
    // The body names the buttons in bold, and that markup has to survive the
    // escaping the rest of the string goes through.
    expect(html).toMatch(/<b>[^<]+<\/b>/);
    expect(html).not.toContain('&lt;b&gt;');
  });

  // The count is decoration that must never be invented: until the backend
  // answers, the line is left out rather than showing a placeholder or a
  // number written into the frontend that would drift.
  it('omits the protocol count until the backend reports one', () => {
    const { ctx, list } = appWithPackets(0);
    ctx.renderPacketList();
    expect(list.innerHTML).not.toContain('empty-count');
    expect(list.innerHTML).not.toContain('{n}');
  });

  // Once the backend answers, the number appears — and it is the backend's
  // number, so it cannot disagree with what the build actually recognises.
  it('shows the protocol count the backend reports', async () => {
    const { ctx, list } = appWithPackets(0);
    await ctx.loadProtocolCount(async (cmd) => {
      expect(cmd).toBe('protocol_count');
      return 2531;
    });
    ctx.renderPacketList();
    expect(list.innerHTML).toContain('empty-count');
    expect(list.innerHTML).toMatch(/2[.,  ]?531/);
  });

  // An older backend has no such command. The pane still has to render.
  it('still renders when the backend has no protocol count', async () => {
    const { ctx, list } = appWithPackets(0);
    await ctx.loadProtocolCount(async () => {
      throw new Error('unknown command');
    });
    ctx.renderPacketList();
    expect(list.innerHTML).toContain('packets-empty');
    expect(list.innerHTML).not.toContain('empty-count');
  });

  // The bug this replaced: the chrome around this pane translated, and the
  // pane itself said "No packets yet" in English regardless of the language.
  it('follows the selected language', () => {
    const { ctx, list } = appWithPackets(0);

    ctx.I18N.apply('tr');
    ctx.renderPacketList();
    expect(list.innerHTML).toContain('Henüz paket yok');
    expect(list.innerHTML).toContain('Başlat');
    expect(list.innerHTML).not.toContain('No packets yet');

    ctx.I18N.apply('de');
    ctx.renderPacketList();
    expect(list.innerHTML).toContain('Noch keine Pakete');

    ctx.I18N.apply('en');
    ctx.renderPacketList();
    expect(list.innerHTML).toContain('No packets yet');
  });
});
