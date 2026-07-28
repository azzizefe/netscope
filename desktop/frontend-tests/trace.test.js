// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp, tcpFrame } from './load-app.js';

const app = loadApp();

const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
const SPAN = '00f067aa0ba902b7';
const SPAN2 = '00f067aa0ba902c8';

function req(headers) {
  return `POST /orders HTTP/1.1\r\nHost: svc\r\n${headers}\r\nContent-Length: 0\r\n\r\n`;
}

describe('parseTraceHeaders', () => {
  it('reads a W3C traceparent', () => {
    const ids = app.parseTraceHeaders(req(`traceparent: 00-${TRACE}-${SPAN}-01`));
    expect(ids).toMatchObject({ traceId: TRACE, spanId: SPAN, format: 'w3c' });
  });

  it('reads the B3 single header, with and without a parent', () => {
    expect(app.parseTraceHeaders(req(`b3: ${TRACE}-${SPAN}-1-${SPAN2}`)))
      .toMatchObject({ traceId: TRACE, spanId: SPAN, parentId: SPAN2, format: 'b3' });
    expect(app.parseTraceHeaders(req(`b3: ${TRACE}-${SPAN}`)))
      .toMatchObject({ traceId: TRACE, spanId: SPAN, parentId: null });
  });

  it('reads the B3 multi-header form', () => {
    const ids = app.parseTraceHeaders(req(
      `X-B3-TraceId: ${TRACE}\r\nX-B3-SpanId: ${SPAN}\r\nX-B3-ParentSpanId: ${SPAN2}`,
    ));
    expect(ids).toMatchObject({ traceId: TRACE, spanId: SPAN, parentId: SPAN2, format: 'b3-multi' });
  });

  it('matches header names case-insensitively, as HTTP requires', () => {
    expect(app.parseTraceHeaders(req(`TraceParent: 00-${TRACE}-${SPAN}-01`))).not.toBeNull();
  });

  /// The all-zero id is what a misconfigured library emits, and the W3C spec
  /// makes it explicitly invalid. Accepting it would collapse every unrelated
  /// request in the capture into a single trace.
  it('rejects the all-zero trace or span id', () => {
    expect(app.parseTraceHeaders(req(`traceparent: 00-${'0'.repeat(32)}-${SPAN}-01`))).toBeNull();
    expect(app.parseTraceHeaders(req(`traceparent: 00-${TRACE}-${'0'.repeat(16)}-01`))).toBeNull();
    expect(app.parseTraceHeaders(req(`b3: ${'0'.repeat(32)}-${SPAN}`))).toBeNull();
  });

  it('rejects version ff, which the spec forbids', () => {
    expect(app.parseTraceHeaders(req(`traceparent: ff-${TRACE}-${SPAN}-01`))).toBeNull();
  });

  /// A future version may append fields; the spec says to tolerate that rather
  /// than reject the header outright.
  it('accepts a future version with extra fields', () => {
    expect(app.parseTraceHeaders(req(`traceparent: 01-${TRACE}-${SPAN}-01-extra`)))
      .toMatchObject({ traceId: TRACE, spanId: SPAN });
  });

  it('rejects ids of the wrong length or with non-hex characters', () => {
    expect(app.parseTraceHeaders(req(`traceparent: 00-${TRACE.slice(0, 30)}-${SPAN}-01`))).toBeNull();
    expect(app.parseTraceHeaders(req(`traceparent: 00-${TRACE}-${SPAN.slice(0, 8)}-01`))).toBeNull();
    expect(app.parseTraceHeaders(req(`traceparent: 00-${'z'.repeat(32)}-${SPAN}-01`))).toBeNull();
  });

  it('returns null for traffic that carries no trace header', () => {
    expect(app.parseTraceHeaders(req('X-Request-Id: abc'))).toBeNull();
    expect(app.parseTraceHeaders('')).toBeNull();
    expect(app.parseTraceHeaders(null)).toBeNull();
  });
});

// ---- Trace assembly ----

function httpFlow(steps, { server = '10.0.0.2', port = 8080, host = null } = {}) {
  return {
    proto: 'HTTP',
    clientAddr: '10.0.0.1', clientPort: 51234,
    serverAddr: server, serverPort: port, serverHost: host,
    bytes: 500,
    pkts: steps.map(([fromClient, text, epoch]) => ({
      fromClient,
      epoch,
      len: 54 + text.length,
      proto: 'HTTP',
      raw: tcpFrame([...text].map((c) => c.charCodeAt(0))),
    })),
  };
}

describe('analyzeTraces', () => {
  it('times a span from its request to its response', () => {
    const [trace] = app.analyzeTraces([httpFlow([
      [true, req(`traceparent: 00-${TRACE}-${SPAN}-01`), 1000],
      [false, 'HTTP/1.1 200 OK\r\n\r\n', 1075],
    ])]);

    expect(trace.traceId).toBe(TRACE);
    expect(trace.spans).toHaveLength(1);
    expect(trace.spans[0].duration).toBe(75);
    expect(trace.spans[0].callee).toBe('10.0.0.2:8080');
  });

  /// The point of correlating on the header rather than the connection: two
  /// calls to different services belong to one trace, and the waterfall shows
  /// them relative to when the trace started.
  it('joins calls to different services into one trace', () => {
    const [trace] = app.analyzeTraces([
      httpFlow([
        [true, req(`traceparent: 00-${TRACE}-${SPAN}-01`), 1000],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 1200],
      ]),
      httpFlow([
        [true, req(`b3: ${TRACE}-${SPAN2}-1-${SPAN}`), 1050],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 1120],
      ], { port: 9090 }),
    ]);

    expect(trace.spans).toHaveLength(2);
    expect(trace.spans.map((s) => s.callee)).toEqual(['10.0.0.2:8080', '10.0.0.2:9090']);
    expect(trace.spans[0].offset).toBe(0);
    expect(trace.spans[1].offset).toBe(50);
    expect(trace.total).toBe(200);
  });

  it('nests a span under a parent that is present in the capture', () => {
    const [trace] = app.analyzeTraces([
      httpFlow([
        [true, req(`b3: ${TRACE}-${SPAN}`), 1000],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 1200],
      ]),
      httpFlow([
        [true, req(`b3: ${TRACE}-${SPAN2}-1-${SPAN}`), 1050],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 1120],
      ], { port: 9090 }),
    ]);

    expect(trace.spans[0].depth).toBe(0);
    expect(trace.spans[1].depth).toBe(1);
  });

  /// A parent that was never captured must not hide its child. Half a trace is
  /// still worth showing; a span nested under something missing is not.
  it('keeps a span at the root when its parent was not captured', () => {
    const [trace] = app.analyzeTraces([httpFlow([
      [true, req(`b3: ${TRACE}-${SPAN2}-1-${SPAN}`), 1000],
      [false, 'HTTP/1.1 200 OK\r\n\r\n', 1100],
    ])]);

    expect(trace.spans[0].depth).toBe(0);
  });

  it('separates unrelated traces', () => {
    const other = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const traces = app.analyzeTraces([
      httpFlow([
        [true, req(`traceparent: 00-${TRACE}-${SPAN}-01`), 1000],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 1050],
      ]),
      httpFlow([
        [true, req(`traceparent: 00-${other}-${SPAN2}-01`), 2000],
        [false, 'HTTP/1.1 200 OK\r\n\r\n', 2300],
      ], { port: 9090 }),
    ]);

    expect(traces).toHaveLength(2);
    // Slowest trace first.
    expect(traces[0].traceId).toBe(other);
  });

  /// A request that never got a reply is still evidence the call happened —
  /// and an unanswered call is usually the one being investigated.
  it('records a request whose response never arrived', () => {
    const [trace] = app.analyzeTraces([httpFlow([
      [true, req(`traceparent: 00-${TRACE}-${SPAN}-01`), 1000],
    ])]);

    expect(trace.spans).toHaveLength(1);
    expect(trace.spans[0].duration).toBeNull();
  });

  it('ignores traffic with no trace headers', () => {
    expect(app.analyzeTraces([httpFlow([
      [true, req('X-Request-Id: abc'), 1000],
      [false, 'HTTP/1.1 200 OK\r\n\r\n', 1050],
    ])])).toEqual([]);
  });
});
