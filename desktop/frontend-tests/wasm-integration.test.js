// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp, tcpFrame, udpFrame, bytes } from './load-app.js';

const noop = () => {};
const fakeEl = () => ({
  style: {},
  classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
  innerHTML: '',
  textContent: '',
  scrollTop: 0,
  clientHeight: 600,
  scrollHeight: 0,
  offsetHeight: 33,
  value: '',
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
    packetCount: fakeEl(),
    filterInput: fakeEl(),
    filterHint: fakeEl(),
    detailTree: fakeEl(),
    hexDump: fakeEl(),
    hexLen: fakeEl(),
    statusText: fakeEl(),
  });

  return { ctx, state, viewPacketsEl };
}

/** Helper to generate raw TCP frame with specific TCP flags */
function tcpFrameFlags(flags, payload = [], opts = {}) {
  const f = tcpFrame(payload, opts);
  f[14 + 20 + 13] = flags; // eth(14) + ip(20) + tcp flags(13)
  return f;
}

/** Helper to generate DNS query payload */
function dnsQuestion(name) {
  const m = new Array(12).fill(0);
  m[5] = 1; // QDCOUNT = 1
  for (const label of name.split('.')) {
    m.push(label.length, ...bytes(label));
  }
  m.push(0, 0, 1, 0, 1); // root, QTYPE A, QCLASS IN
  return m;
}

describe('WASM Filter Engine Integration Tests', () => {
  it('initializes WASM NetscopeFilter inside the app context', () => {
    const { ctx } = setupTestCtx();
    expect(ctx.NetscopeFilter).toBeDefined();
    expect(typeof ctx.NetscopeFilter.compile).toBe('function');
    expect(typeof ctx.NetscopeFilter.matchesBatch).toBe('function');
  });

  it('filters incoming Tauri packet batch (onPacketBatch) using WASM engine', () => {
    const { ctx, state } = setupTestCtx();
    state.view = 'packets';

    const mockTauriBatch = [
      {
        id: 1,
        protocol: 'TLS',
        src_addr: '192.168.1.5',
        dst_addr: '142.250.74.46',
        src_port: 51000,
        dst_port: 443,
        length: 1200,
        summary: 'TLS Client Hello',
        raw: tcpFrame(bytes('client hello'), { srcPort: 51000, dstPort: 443 }),
      },
      {
        id: 2,
        protocol: 'DNS',
        src_addr: '192.168.1.5',
        dst_addr: '8.8.8.8',
        src_port: 51001,
        dst_port: 53,
        length: 80,
        summary: 'Standard query A example.com',
        raw: udpFrame(dnsQuestion('example.com'), { srcPort: 51001, dstPort: 53 }),
      },
      {
        id: 3,
        protocol: 'HTTP',
        src_addr: '192.168.1.5',
        dst_addr: '93.184.216.34',
        src_port: 51002,
        dst_port: 80,
        length: 350,
        summary: 'GET /index.html HTTP/1.1',
        raw: tcpFrame(bytes('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'), { srcPort: 51002, dstPort: 80 }),
      },
      {
        id: 4,
        protocol: 'TCP',
        src_addr: '10.0.0.1',
        dst_addr: '10.0.0.2',
        src_port: 40000,
        dst_port: 22,
        length: 64,
        summary: 'SSH Connection',
        raw: tcpFrameFlags(0x02, [], { srcPort: 40000, dstPort: 22 }),
      },
    ];

    // Simulate Tauri batch IPC payload delivery
    ctx.onPacketBatch({ payload: mockTauriBatch });
    expect(state.packets.length).toBe(4);

    // Apply WASM filter for TLS packets
    state.filterText = 'tls';
    ctx.renderPacketList();
    expect(state.filteredPackets.length).toBe(1);
    expect(state.filteredPackets[0].id).toBe(1);

    // Apply WASM filter for port 80
    state.filterText = 'tcp.port == 80';
    ctx.renderPacketList();
    expect(state.filteredPackets.length).toBe(1);
    expect(state.filteredPackets[0].id).toBe(3);

    // Apply WASM filter for length ordering
    state.filterText = 'frame.len > 1000';
    ctx.renderPacketList();
    expect(state.filteredPackets.length).toBe(1);
    expect(state.filteredPackets[0].id).toBe(1);

    // Apply boolean WASM filter expression
    state.filterText = 'dns || http';
    ctx.renderPacketList();
    expect(state.filteredPackets.length).toBe(2);
    expect(state.filteredPackets.map((p) => p.id)).toEqual([2, 3]);
  });

  it('updates filteredPackets in real-time during live packet streaming (onPacket)', () => {
    const { ctx, state } = setupTestCtx();
    state.view = 'packets';
    state.filterText = 'tcp.flags.syn == 1';

    const synPkt = {
      id: 100,
      protocol: 'TCP',
      src_addr: '10.0.0.5',
      dst_addr: '10.0.0.10',
      src_port: 55000,
      dst_port: 80,
      length: 60,
      summary: '[SYN]',
      raw: tcpFrameFlags(0x02, [], { srcPort: 55000, dstPort: 80 }),
    };

    const ackPkt = {
      id: 101,
      protocol: 'TCP',
      src_addr: '10.0.0.5',
      dst_addr: '10.0.0.10',
      src_port: 55000,
      dst_port: 80,
      length: 60,
      summary: '[ACK]',
      raw: tcpFrameFlags(0x10, [], { srcPort: 55000, dstPort: 80 }),
    };

    // Live stream SYN packet via onPacket
    ctx.onPacket({ payload: synPkt });
    expect(state.packets.length).toBe(1);
    expect(state.filteredPackets.length).toBe(1);
    expect(state.filteredPackets[0].id).toBe(100);

    // Live stream ACK packet (should be filtered out by WASM engine)
    ctx.onPacket({ payload: ackPkt });
    expect(state.packets.length).toBe(2);
    expect(state.filteredPackets.length).toBe(1);
    expect(state.filteredPackets[0].id).toBe(100);
  });

  it('integrates WASM filter engine with row coloring rules (colorRuleFor)', () => {
    const { ctx, state } = setupTestCtx();

    state.coloring = [
      { name: 'DNS Traffic', filter: 'dns', color: '#00ff00', enabled: true },
      { name: 'HTTP Requests', filter: 'http.request.method == "POST"', color: '#ff00ff', enabled: true },
    ];

    const dnsPkt = {
      protocol: 'DNS',
      src_addr: '192.168.1.1',
      dst_addr: '8.8.8.8',
      src_port: 5000,
      dst_port: 53,
      length: 70,
      raw: udpFrame(dnsQuestion('example.com')),
    };

    const httpPostPkt = {
      protocol: 'HTTP',
      src_addr: '192.168.1.1',
      dst_addr: '1.1.1.1',
      src_port: 5001,
      dst_port: 80,
      length: 200,
      raw: tcpFrame(bytes('POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\ndata')),
    };

    const tcpOtherPkt = {
      protocol: 'TCP',
      src_addr: '192.168.1.1',
      dst_addr: '1.1.1.1',
      src_port: 5002,
      dst_port: 8080,
      length: 60,
      raw: tcpFrame([]),
    };

    const dnsRule = ctx.colorRuleFor(dnsPkt);
    expect(dnsRule).not.toBeNull();
    expect(dnsRule.color).toBe('#00ff00');

    const httpRule = ctx.colorRuleFor(httpPostPkt);
    expect(httpRule).not.toBeNull();
    expect(httpRule.color).toBe('#ff00ff');

    const unknownRule = ctx.colorRuleFor(tcpOtherPkt);
    expect(unknownRule).toBeNull();
  });

  it('handles invalid filter strings gracefully without throwing in renderPacketList', () => {
    const { ctx, state } = setupTestCtx();
    state.view = 'packets';

    state.packets = [
      { id: 1, protocol: 'TCP', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 80, dst_port: 5000, length: 64, summary: 'TCP Packet', raw: [] },
    ];

    // Invalid syntax should fail WASM compilation and fall back gracefully
    state.filterText = 'tcp &&';
    expect(() => ctx.renderPacketList()).not.toThrow();

    // When WASM compilation fails, fallback filter matches string or returns packets
    expect(state.filteredPackets).toBeDefined();
  });

  it('resets selectedIndex and detail view when WASM filter excludes the currently selected packet', () => {
    const { ctx, state, viewPacketsEl } = setupTestCtx();
    state.view = 'packets';

    state.packets = [
      { id: 1, protocol: 'HTTP', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 80, dst_port: 5000, length: 100, summary: 'HTTP GET', raw: [] },
      { id: 2, protocol: 'DNS', src_addr: '10.0.0.1', dst_addr: '8.8.8.8', src_port: 53, dst_port: 5000, length: 80, summary: 'DNS Query', raw: [] },
    ];

    ctx.renderPacketList();

    // Select packet 1 (HTTP)
    state.selectedPacket = state.packets[0];
    state.selectedIndex = 0;
    viewPacketsEl.classList.add('with-detail');

    // Change filter to DNS
    state.filterText = 'dns';
    ctx.renderPacketList();

    // Selected packet (HTTP) is not in filteredPackets (DNS only), so selection must reset
    expect(state.selectedIndex).toBe(-1);
    expect(state.selectedPacket).toBeNull();
    expect(viewPacketsEl.classList.contains('with-detail')).toBe(false);
  });
});
