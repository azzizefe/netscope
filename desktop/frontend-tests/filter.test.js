import { describe, it, expect } from 'vitest';
import { loadFilter } from './load-app.js';

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

describe('NetscopeFilter — invalid syntax returns null (substring fallback)', () => {
  it.each(['google', '', 'ip.addr ==', '(tcp', 'unknownfield == 5', 'tcp &&'])(
    'does not compile %j',
    (expr) => {
      expect(F.compile(expr)).toBeNull();
    },
  );
});
