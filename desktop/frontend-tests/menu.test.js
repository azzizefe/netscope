import { describe, it, expect } from 'vitest';
import { loadApp } from './load-app.js';

const app = loadApp();

const P = (o) => ({
  timestamp: '10:00:00', src_addr: '10.0.0.1', dst_addr: '8.8.8.8',
  src_port: 1234, dst_port: 80, protocol: 'HTTP', length: 100, summary: 'HTTP GET /', ...o,
});

describe('computeProtocolHierarchy', () => {
  it('counts, sums bytes and computes share', () => {
    const pkts = [P({ protocol: 'HTTP', length: 100 }), P({ protocol: 'HTTP', length: 200 }), P({ protocol: 'DNS', length: 50 })];
    const h = app.computeProtocolHierarchy(pkts);
    expect(h[0]).toMatchObject({ protocol: 'HTTP', count: 2, bytes: 300 });
    expect(h[0].pct).toBeCloseTo(66.67, 1);
    expect(h.find((e) => e.protocol === 'DNS').count).toBe(1);
  });
});

describe('computeEndpoints', () => {
  it('aggregates tx/rx per address', () => {
    const pkts = [
      P({ src_addr: 'A', dst_addr: 'B', length: 100 }),
      P({ src_addr: 'B', dst_addr: 'A', length: 40 }),
    ];
    const e = app.computeEndpoints(pkts);
    const a = e.find((x) => x.addr === 'A');
    expect(a.packets).toBe(2);
    expect(a.bytes).toBe(140);
    expect(a.tx).toBe(1);
    expect(a.rx).toBe(1);
  });
});

describe('computeVoipCalls', () => {
  it('lists only SIP packets', () => {
    const pkts = [P({ protocol: 'SIP', summary: 'SIP INVITE — sip:bob@x' }), P({ protocol: 'HTTP' })];
    const calls = app.computeVoipCalls(pkts);
    expect(calls).toHaveLength(1);
    expect(calls[0].summary).toContain('INVITE');
  });
});

describe('computeCredentials', () => {
  it('flags cleartext credential protocols', () => {
    const pkts = [
      P({ protocol: 'FTP', summary: 'FTP USER alice' }),
      P({ protocol: 'IMAP', summary: 'IMAP a1 LOGIN ⋯' }),
      P({ protocol: 'HTTPS', summary: 'TLS handshake' }),
      P({ protocol: 'DNS', summary: 'DNS Query' }),
    ];
    const creds = app.computeCredentials(pkts);
    expect(creds.map((c) => c.protocol)).toEqual(['FTP', 'IMAP']);
  });
});

describe('computeWlanTraffic', () => {
  it('aggregates SSIDs from beacon/probe summaries', () => {
    const pkts = [
      P({ protocol: '802.11', summary: '802.11 Beacon — "MyWiFi"' }),
      P({ protocol: '802.11', summary: '802.11 Beacon — "MyWiFi"' }),
      P({ protocol: '802.11', summary: '802.11 Beacon — <hidden>' }),
      P({ protocol: '802.11', summary: '802.11 ACK' }),
    ];
    const w = app.computeWlanTraffic(pkts);
    expect(w[0]).toEqual({ ssid: 'MyWiFi', count: 2 });
    expect(w.find((x) => x.ssid === '<hidden>').count).toBe(1);
  });
});

describe('packetsToCSV', () => {
  it('emits a header and escapes commas', () => {
    const csv = app.packetsToCSV([P({ summary: 'GET /a, /b', protocol: 'HTTP' })]);
    const lines = csv.split('\n');
    expect(lines[0]).toBe('No,Time,Source,Destination,Protocol,Length,Info');
    expect(lines[1]).toContain('"GET /a, /b"');
  });
});

describe('packetsToJSON', () => {
  it('produces parseable JSON with expected fields', () => {
    const json = JSON.parse(app.packetsToJSON([P({ protocol: 'DNS' })]));
    expect(json[0]).toMatchObject({ protocol: 'DNS', src: '10.0.0.1' });
  });
});

describe('firewallRulesText', () => {
  it('generates netsh and iptables rules', () => {
    const text = app.firewallRulesText(['1.2.3.4']);
    expect(text).toContain('netsh advfirewall firewall add rule');
    expect(text).toContain('iptables -A OUTPUT -d 1.2.3.4 -j DROP');
  });
  it('handles no blocked IPs', () => {
    expect(app.firewallRulesText([])).toContain('No IPs');
  });
});
