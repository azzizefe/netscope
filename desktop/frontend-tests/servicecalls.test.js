// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
import { describe, it, expect } from 'vitest';
import { loadApp, tcpFrame, udpFrame } from './load-app.js';

const app = loadApp();

const SYN = 0x02;
const ACK = 0x10;
const PSH = 0x08;

/** A TCP frame with the given flags and payload length. */
function seg(flags, payloadLen = 0) {
  const frame = tcpFrame(new Array(payloadLen).fill(0x41));
  frame[14 + 20 + 13] = flags; // flags byte: 14 eth + 20 ip + offset 13 in TCP
  return frame;
}

/** A flow whose packets are `[fromClient, flags, payloadLen, epoch]` tuples. */
function flow(steps, extra = {}) {
  return {
    proto: 'TCP',
    clientAddr: '10.0.0.1',
    clientPort: 51234,
    serverAddr: '10.0.0.2',
    serverPort: 8080,
    serverHost: null,
    bytes: 1000,
    pkts: steps.map(([fromClient, flags, payloadLen, epoch]) => ({
      fromClient, epoch, len: 54 + payloadLen, proto: 'TCP', raw: seg(flags, payloadLen),
    })),
    ...extra,
  };
}

describe('analyzeServiceCalls', () => {
  it('measures service time from request payload to response payload', () => {
    const [edge] = app.analyzeServiceCalls([flow([
      [true, PSH | ACK, 100, 1000],
      [false, PSH | ACK, 500, 1030],
    ])]);

    expect(edge.callee).toBe('10.0.0.2:8080');
    expect(edge.caller).toBe('10.0.0.1');
    expect(edge.service.count).toBe(1);
    expect(edge.service.median).toBe(30);
  });

  /// The claim the whole view rests on. A bare ACK is the TCP stack replying,
  /// not the service — pairing on it would report network round-trip time
  /// under a "service time" heading, which is the one number someone opens
  /// this view to tell apart.
  it('does not treat a bare ACK as a response', () => {
    const [edge] = app.analyzeServiceCalls([flow([
      [true, PSH | ACK, 100, 1000],
      [false, ACK, 0, 1002],       // stack acknowledges in 2ms
      [false, PSH | ACK, 500, 1250], // service answers in 250ms
    ])]);

    expect(edge.service.count).toBe(1);
    expect(edge.service.median).toBe(250);
  });

  /// Network latency comes from the handshake, where the callee has not yet
  /// done any work, and is reported separately.
  it('measures network round-trip from the handshake', () => {
    const [edge] = app.analyzeServiceCalls([flow([
      [true, SYN, 0, 1000],
      [false, SYN | ACK, 0, 1012],
      [true, PSH | ACK, 100, 1020],
      [false, PSH | ACK, 200, 1120],
    ])]);

    expect(edge.network.median).toBe(12);
    expect(edge.service.median).toBe(100);
  });

  it('aggregates repeated calls and reports percentiles', () => {
    const steps = [];
    let t = 1000;
    for (const delay of [10, 20, 30, 40, 500]) {
      steps.push([true, PSH | ACK, 50, t]);
      steps.push([false, PSH | ACK, 50, t + delay]);
      t += delay + 100;
    }
    const [edge] = app.analyzeServiceCalls([flow(steps)]);

    expect(edge.service.count).toBe(5);
    expect(edge.service.median).toBe(30);
    expect(edge.service.max).toBe(500);
  });

  /// One request is outstanding at a time. A second client payload before the
  /// response arrives must not start a competing measurement, or a pipelined
  /// connection reports latencies that were never observed.
  it('keeps one request outstanding at a time', () => {
    const [edge] = app.analyzeServiceCalls([flow([
      [true, PSH | ACK, 50, 1000],
      [true, PSH | ACK, 50, 1005],
      [false, PSH | ACK, 50, 1100],
    ])]);

    expect(edge.service.count).toBe(1);
    expect(edge.service.median).toBe(100); // from the first request, not the second
  });

  it('groups several flows to the same service into one edge', () => {
    const edges = app.analyzeServiceCalls([
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1020]]),
      flow([[true, PSH | ACK, 50, 2000], [false, PSH | ACK, 50, 2040]]),
    ]);

    expect(edges).toHaveLength(1);
    expect(edges[0].flows).toBe(2);
    expect(edges[0].service.count).toBe(2);
  });

  it('separates services running on different ports of one host', () => {
    const edges = app.analyzeServiceCalls([
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1020]]),
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1020]], { serverPort: 9090 }),
    ]);

    expect(edges.map((e) => e.callee).sort())
      .toEqual(['10.0.0.2:8080', '10.0.0.2:9090']);
  });

  it('prefers the resolved hostname when there is one', () => {
    const [edge] = app.analyzeServiceCalls([
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1020]], { serverHost: 'orders' }),
    ]);
    expect(edge.callee).toBe('orders:8080');
  });

  /// Slowest first — the view exists to find what is holding the chain up.
  it('orders the slowest service first', () => {
    const edges = app.analyzeServiceCalls([
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1010]]),
      flow([[true, PSH | ACK, 50, 1000], [false, PSH | ACK, 50, 1400]], { serverPort: 9090 }),
    ]);

    expect(edges[0].callee).toBe('10.0.0.2:9090');
    expect(edges[0].service.median).toBe(400);
  });

  describe('reports nothing rather than guessing', () => {
    it('ignores UDP, where there is no handshake or stream to pair on', () => {
      const udp = {
        proto: 'DNS',
        clientAddr: '10.0.0.1', clientPort: 51234,
        serverAddr: '10.0.0.2', serverPort: 53,
        serverHost: null, bytes: 200,
        pkts: [
          { fromClient: true, epoch: 1000, len: 70, proto: 'DNS', raw: udpFrame(new Array(28).fill(0)) },
          { fromClient: false, epoch: 1020, len: 90, proto: 'DNS', raw: udpFrame(new Array(48).fill(0)) },
        ],
      };
      expect(app.analyzeServiceCalls([udp])).toEqual([]);
    });

    it('leaves latency null when a flow carried no request/response pair', () => {
      const [edge] = app.analyzeServiceCalls([flow([
        [true, PSH | ACK, 50, 1000],
        [true, PSH | ACK, 50, 1010],
      ])]);
      expect(edge.service).toBeNull();
    });

    it('skips packets with no timestamp instead of inventing a delta', () => {
      const [edge] = app.analyzeServiceCalls([flow([
        [true, PSH | ACK, 50, null],
        [false, PSH | ACK, 50, 1020],
      ])]);
      expect(edge.service).toBeNull();
    });
  });
});
