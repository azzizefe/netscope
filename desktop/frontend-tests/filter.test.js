// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadFilter, tcpFrame, udpFrame, bytes } from './load-app.js';

const F = loadFilter();

// Frontend packet shape (a subset of PacketInfo) used by the filter.
const tls443 = {
  protocol: 'TLS', src_addr: '192.168.1.5', dst_addr: '142.250.74.46',
  src_port: 51000, dst_port: 443, length: 1200,
};
const dns = {
  protocol: 'DNS', src_addr: '192.168.1.5', dst_addr: '8.8.8.8',
  src_port: 51001, dst_port: 53, length: 80,
};
const v6 = {
  protocol: 'TCP', src_addr: '2606:4700::1', dst_addr: '2001:db8::5',
  src_port: 40000, dst_port: 443, length: 100,
};

const hit = (expr, pkt) => {
  const c = F.compile(expr);
  expect(c, `"${expr}" should compile`).not.toBeNull();
  return c.matches(pkt);
};

describe('NetscopeFilter — protocol predicates', () => {
  it('matches by name and transport', () => {
    expect(hit('tls', tls443)).toBe(true);
    expect(hit('tcp', tls443)).toBe(true); // transport
    expect(hit('udp', tls443)).toBe(false);
    expect(hit('dns', dns)).toBe(true);
    expect(hit('udp', dns)).toBe(true);
  });
  it('websocket and its ws alias', () => {
    const wsPkt = { protocol: 'WebSocket', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 50000, dst_port: 8080, length: 64 };
    expect(hit('websocket', wsPkt)).toBe(true);
    expect(hit('ws', wsPkt)).toBe(true);
    expect(hit('tcp', wsPkt)).toBe(true); // rides on TCP
    expect(hit('websocket', tls443)).toBe(false);
  });
  it('vxlan predicate', () => {
    const vx = { protocol: 'VXLAN', src_addr: '192.168.0.1', dst_addr: '192.168.0.2', src_port: 50000, dst_port: 4789, length: 148 };
    expect(hit('vxlan', vx)).toBe(true);
    expect(hit('udp', vx)).toBe(true); // rides on UDP
    expect(hit('vxlan', dns)).toBe(false);
  });
  it('http2 and grpc predicates', () => {
    const h2 = { protocol: 'HTTP/2', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 50000, dst_port: 8080, length: 64 };
    expect(hit('http2', h2)).toBe(true);
    expect(hit('tcp', h2)).toBe(true); // rides on TCP
    expect(hit('http', h2)).toBe(false); // HTTP/1.x is a different predicate
    const g = { protocol: 'gRPC', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 50000, dst_port: 50051, length: 120 };
    expect(hit('grpc', g)).toBe(true);
    expect(hit('tcp', g)).toBe(true);
    expect(hit('http2', g)).toBe(false); // labelled by the more specific protocol
  });
});

describe('NetscopeFilter — address fields', () => {
  it('ip.addr matches either endpoint; sides are specific', () => {
    expect(hit('ip.addr == 142.250.74.46', tls443)).toBe(true);
    expect(hit('ip.addr == 192.168.1.5', tls443)).toBe(true);
    expect(hit('ip.dst == 142.250.74.46', tls443)).toBe(true);
    expect(hit('ip.src == 142.250.74.46', tls443)).toBe(false);
  });
  it('!= means neither endpoint', () => {
    expect(hit('ip.addr != 10.0.0.1', tls443)).toBe(true);
    expect(hit('ip.addr != 142.250.74.46', tls443)).toBe(false);
  });
  it('handles IPv6', () => {
    expect(hit('ip.addr == 2606:4700::1', v6)).toBe(true);
    expect(hit('ipv6', v6)).toBe(true);
    expect(hit('ipv4', v6)).toBe(false);
  });
});

describe('NetscopeFilter — ports and length', () => {
  it('port fields respect transport', () => {
    expect(hit('port == 443', tls443)).toBe(true);
    expect(hit('tcp.port == 443', tls443)).toBe(true);
    expect(hit('udp.port == 443', tls443)).toBe(false);
    expect(hit('tcp.port != 80', tls443)).toBe(true);
  });
  it('frame.len ordering', () => {
    expect(hit('frame.len > 1000', tls443)).toBe(true);
    expect(hit('len >= 1200', tls443)).toBe(true);
    expect(hit('length < 500', tls443)).toBe(false);
  });
});

describe('NetscopeFilter — boolean logic', () => {
  it('and/or/not with precedence', () => {
    expect(hit('tcp && tcp.port == 443', tls443)).toBe(true);
    expect(hit('udp || tls', tls443)).toBe(true);
    expect(hit('tcp && udp', tls443)).toBe(false);
    expect(hit('!udp', tls443)).toBe(true);
    expect(hit('not udp', tls443)).toBe(true);
    expect(hit('udp && arp || tls', tls443)).toBe(true); // && binds tighter
  });
  it('parentheses group', () => {
    expect(hit('tcp && (tls || dns)', tls443)).toBe(true);
    expect(hit('udp && (tls || dns)', tls443)).toBe(false);
  });
  it('contains operator', () => {
    expect(hit('ip.dst contains "142.250"', tls443)).toBe(true);
    expect(hit('ip.src contains "999"', tls443)).toBe(false);
  });
});

// ---- Protocol fields parsed from raw frame bytes ----

/** tcpFrame with a specific TCP flags byte (offset 13 in the TCP header). */
function tcpFrameFlags(flags, payload = [], opts = {}) {
  const f = tcpFrame(payload, opts);
  f[14 + 20 + 13] = flags; // eth(14) + ip(20) + flags byte
  return f;
}

/** Minimal DNS message with one question for `name`. */
function dnsQuestion(name) {
  const m = new Array(12).fill(0);
  m[5] = 1; // QDCOUNT = 1
  for (const label of name.split('.')) { m.push(label.length, ...bytes(label)); }
  m.push(0, 0, 1, 0, 1); // root, QTYPE A, QCLASS IN
  return m;
}

describe('NetscopeFilter — tcp.flags fields', () => {
  const syn = { protocol: 'TCP', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 1, dst_port: 80, length: 54, raw: tcpFrameFlags(0x02) };
  const rstAck = { ...syn, raw: tcpFrameFlags(0x14) };
  it('reads individual flag bits', () => {
    expect(hit('tcp.flags.syn == 1', syn)).toBe(true);
    expect(hit('tcp.flags.ack == 0', syn)).toBe(true);
    expect(hit('tcp.flags.rst == 1', syn)).toBe(false);
    expect(hit('tcp.flags.rst == 1 && tcp.flags.ack == 1', rstAck)).toBe(true);
  });
  it('is false (not true-by-absence) on non-TCP packets', () => {
    const udp = { protocol: 'DNS', raw: udpFrame(dnsQuestion('a.b')), length: 60 };
    expect(hit('tcp.flags.syn == 1', udp)).toBe(false);
    expect(hit('tcp.flags.syn == 0', udp)).toBe(false);
  });
});

describe('NetscopeFilter — http fields', () => {
  const req = {
    protocol: 'HTTP', src_addr: '10.0.0.1', dst_addr: '10.0.0.2', src_port: 50000, dst_port: 80, length: 200,
    raw: tcpFrame(bytes('POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\nhi')),
  };
  const resp = { ...req, raw: tcpFrame(bytes('HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n')) };
  it('request method, uri, host', () => {
    expect(hit('http.request.method == "POST"', req)).toBe(true);
    expect(hit('http.request.method == post', req)).toBe(true); // case-insensitive
    expect(hit('http.request.method == GET', req)).toBe(false);
    expect(hit('http.request.uri contains "/api"', req)).toBe(true);
    expect(hit('http.host == example.com', req)).toBe(true);
    expect(hit('http.response.code == 200', req)).toBe(false); // it's a request
  });
  it('response code with ordering', () => {
    expect(hit('http.response.code == 404', resp)).toBe(true);
    expect(hit('http.response.code >= 400', resp)).toBe(true);
    expect(hit('http.request.method == GET', resp)).toBe(false); // it's a response
  });
});

describe('NetscopeFilter — dns.qry.name and info', () => {
  it('extracts the DNS question name', () => {
    const q = { protocol: 'DNS', src_port: 51001, dst_port: 53, length: 80, raw: udpFrame(dnsQuestion('example.com'), { dstPort: 53 }) };
    expect(hit('dns.qry.name == example.com', q)).toBe(true);
    expect(hit('dns.qry.name contains "example"', q)).toBe(true);
    expect(hit('dns.qry.name == other.org', q)).toBe(false);
    expect(hit('dns.qry.name contains "example"', tls443)).toBe(false); // non-DNS
  });
  it('info searches the summary column', () => {
    const p = { ...tls443, summary: 'TLS — google.com (HTTPS)' };
    expect(hit('info contains google', p)).toBe(true);
    expect(hit('info contains yahoo', p)).toBe(false);
  });
});

describe('NetscopeFilter — invalid syntax returns null (substring fallback)', () => {
  it.each(['google', '', 'ip.addr ==', '(tcp', 'unknownfield == 5', 'tcp &&'])(
    'does not compile %j',
    (expr) => {
      expect(F.compile(expr)).toBeNull();
    },
  );
});

describe('NetscopeFilter.suggest — autocomplete (ROADMAP §6.2)', () => {
  const values = (text) => F.suggest(text).items.map((i) => i.value);

  it('suggests fields and protocols for a bare prefix', () => {
    const v = values('tc');
    expect(v).toContain('tcp'); // protocol keyword
    expect(v).toContain('tcp.port'); // field
    expect(F.suggest('tc').start).toBe(0);
  });

  it('offers operators once a field is complete', () => {
    const v = values('tcp.port ');
    expect(v).toContain('==');
    expect(v).toContain('>');
    // The active token starts at the end (nothing typed yet).
    expect(F.suggest('tcp.port ').start).toBe('tcp.port '.length);
  });

  it('offers values after an operator, scoped to the field', () => {
    expect(values('tcp.port == ')).toContain('443');
    expect(values('http.request.method == ')).toContain('GET');
    expect(values('http.response.code == ')).toContain('404');
  });

  it('filters candidates by the partial token and reports its start', () => {
    const s = F.suggest('tcp.port == 4');
    expect(s.items.map((i) => i.value)).toContain('443');
    expect(s.items.map((i) => i.value)).not.toContain('80');
    expect(s.start).toBe('tcp.port == '.length);
  });

  it('suggests booleans only after a first term', () => {
    expect(values('tcp ')).toContain('&&');
    expect(values('')).not.toContain('&&');
  });
});
