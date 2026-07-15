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

function setupTestCtx() {
  const ctx = loadApp();
  const { state, els } = ctx.__netscopeTest;
  ctx.state = state;
  
  const classes = new Set();
  const viewPacketsEl = {
    classList: {
      add(c) { classes.add(c); },
      remove(c) { classes.delete(c); },
      contains(c) { return classes.has(c); },
    },
  };

  ctx.document.querySelector = (sel) => {
    if (sel === '#view-packets') return viewPacketsEl;
    return fakeEl();
  };

  Object.assign(els, {
    packetTable: fakeEl(),
    packetList: fakeEl(),
    packetHeader: { offsetHeight: 33 },
    filterInput: fakeEl(),
    detailTree: fakeEl(),
    hexDump: fakeEl(),
    hexLen: fakeEl(),
  });

  return { ctx, state, viewPacketsEl };
}

describe('Frontend Packet Eviction & Selection Tracking', () => {
  it('keeps selection locked to the same packet object when elements are evicted from the front', () => {
    const { ctx, state } = setupTestCtx();

    // Ingest some packets
    for (let i = 0; i < 50; i++) {
      state.packets.push({
        id: i,
        protocol: 'TCP',
        src_addr: '10.0.0.1',
        dst_addr: '10.0.0.2',
        src_port: 1000,
        dst_port: 80,
        length: 60,
        summary: `packet number ${i}`,
        raw: [],
      });
    }

    ctx.renderPacketList();
    
    // Select the 10th packet (index 10, value `packet number 10`)
    const targetPacket = state.packets[10];
    ctx.showDetail(10);
    expect(state.selectedIndex).toBe(10);

    // Evict 5 packets off the front
    for (let i = 0; i < 5; i++) {
      state.packets.shift();
    }

    // Render again
    ctx.renderPacketList();

    // The index should shift down by 5, tracking the selected packet
    expect(state.selectedIndex).toBe(5);
    expect(state.filteredPackets[state.selectedIndex]).toBe(targetPacket);
  });

  it('safely resets selectedIndex to -1 and removes detail view class if the selected packet is evicted', () => {
    const { ctx, state, viewPacketsEl } = setupTestCtx();

    // Ingest some packets
    for (let i = 0; i < 20; i++) {
      state.packets.push({
        id: i,
        protocol: 'TCP',
        src_addr: '10.0.0.1',
        dst_addr: '10.0.0.2',
        src_port: 1000,
        dst_port: 80,
        length: 60,
        summary: `packet number ${i}`,
        raw: [],
      });
    }

    ctx.renderPacketList();

    // Select the first packet (index 0, value `packet number 0`)
    const targetPacket = state.packets[0];
    ctx.showDetail(0);
    expect(state.selectedIndex).toBe(0);
    viewPacketsEl.classList.add('with-detail');

    // Evict the first 5 packets (including the selected one at index 0)
    for (let i = 0; i < 5; i++) {
      state.packets.shift();
    }

    // Render again
    ctx.renderPacketList();

    // Selection index should be reset to -1, and 'with-detail' class should be removed
    expect(state.selectedIndex).toBe(-1);
    expect(viewPacketsEl.classList.contains('with-detail')).toBe(false);
  });
});
