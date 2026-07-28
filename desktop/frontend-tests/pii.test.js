// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp } from './load-app.js';

const app = loadApp();

const kinds = (text) => app.findSensitiveData(text).map((f) => f.kind);
const values = (text, kind) =>
  app.findSensitiveData(text).filter((f) => f.kind === kind).map((f) => f.value);

describe('findSensitiveData — credentials', () => {
  it('finds a password in a form body', () => {
    const post = 'POST /login HTTP/1.1\r\n\r\nuser=efe&password=hunter2&remember=1';
    expect(values(post, 'Credential')).toContain('hunter2');
  });

  it('finds the common credential parameter names', () => {
    for (const name of ['password', 'passwd', 'pwd', 'api_key', 'apikey',
      'access_token', 'client_secret', 'session_id']) {
      expect(values(`${name}=s3cretvalue`, 'Credential')).toContain('s3cretvalue');
    }
  });

  it('stops at the parameter separator, not at the end of the body', () => {
    expect(values('password=hunter2&next=/home', 'Credential')).toEqual(['hunter2']);
  });

  it('decodes HTTP Basic, which is base64 rather than encryption', () => {
    // "efe:hunter2"
    const header = 'Authorization: Basic ZWZlOmh1bnRlcjI=';
    const found = app.findSensitiveData(header).find((f) => f.kind === 'Basic auth');
    expect(found.value).toBe('efe:hunter2');
  });

  it('finds a bearer token', () => {
    expect(values('Authorization: Bearer abcdef0123456789', 'Bearer token'))
      .toContain('abcdef0123456789');
  });
});

describe('findSensitiveData — issuer-prefixed keys', () => {
  it('recognises each vendor prefix', () => {
    const cases = {
      'AKIAIOSFODNN7EXAMPLE': 'AWS access key',
      'ghp_1234567890abcdefghijklmnopqrstuvwxyz': 'GitHub token',
      // Google keys are AIza plus exactly 35 characters.
      [`AIza${'SyD-1234567890abcdefghijklmnopqrst'.padEnd(35, 'x')}`]: 'Google API key',
      'xoxb-1234567890-abcdefghij': 'Slack token',
      'sk_live_abcdefghij1234567890': 'Stripe live key',
    };
    for (const [key, label] of Object.entries(cases)) {
      const found = app.findSensitiveData(`token=${key}`).find((f) => f.note === label);
      expect(found, `${label} not found`).toBeTruthy();
      expect(found.value).toBe(key);
    }
  });

  it('finds a private key block', () => {
    expect(kinds('-----BEGIN RSA PRIVATE KEY-----\nMIIE...')).toContain('API key');
  });

  it('finds a JWT and says its claims are readable', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u';
    const found = app.findSensitiveData(`Cookie: t=${jwt}`).find((f) => f.kind === 'JWT');
    expect(found.value).toBe(jwt);
    expect(found.note).toMatch(/readable/);
  });

  /// A long random string is not a key. Matching on "looks random" would flag
  /// every session id, hash and nonce in the capture.
  it('does not flag an arbitrary long token as a vendor key', () => {
    const found = app.findSensitiveData('x=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg');
    expect(found.some((f) => f.kind === 'API key')).toBe(false);
  });
});

describe('findSensitiveData — card numbers', () => {
  /// The quality gate for the whole feature. Without Luhn every 16-digit
  /// order id and timestamp pair is reported as a credit card, and a finder
  /// that cries wolf gets switched off.
  it('accepts only Luhn-valid numbers', () => {
    expect(values('card=4111111111111111', 'Card number')).toEqual(['4111111111111111']);
    // Same length and prefix, one digit changed — fails the checksum.
    expect(values('card=4111111111111112', 'Card number')).toEqual([]);
  });

  it('ignores a 16-digit number that is not a card', () => {
    expect(values('order_id=1234567890123456', 'Card number')).toEqual([]);
    expect(values('ts=17538400001234567', 'Card number')).toEqual([]);
  });

  /// Luhn on its own is a weak filter — one in ten random numbers of the right
  /// length passes it, and several identifiers carry a Luhn digit *by design*.
  /// An IMEI is Luhn-valid, fifteen digits, and often starts with 4, so a
  /// Luhn-only check reported every phone in the capture as a Visa card. This
  /// is the false positive that made the panel untrustworthy.
  it('rejects a Luhn-valid number that no issuer could have issued', () => {
    // A real IMEI: passes Luhn, starts with 4, but Visa does not issue 15 digits.
    expect(app.luhnValid('490154203237518')).toBe(true);
    expect(values('imei=490154203237518', 'Card number')).toEqual([]);

    // 16 digits starting 9 — Luhn-valid, but no issuer range begins there.
    expect(values('n=9999999999999995', 'Card number')).toEqual([]);
  });

  it('accepts each issuer only at a length that issuer uses', () => {
    // Amex is 15 digits and starts 34/37.
    expect(values('c=378282246310005', 'Card number')).toEqual(['378282246310005']);
    // The same prefix at 16 digits is not an Amex, and nothing else claims 37.
    expect(values('c=3782822463100051', 'Card number')).toEqual([]);
  });

  it('accepts the separators a form actually sends', () => {
    expect(values('card=4111 1111 1111 1111', 'Card number')).toEqual(['4111111111111111']);
    expect(values('card=4111-1111-1111-1111', 'Card number')).toEqual(['4111111111111111']);
  });

  it('names the card network', () => {
    const net = (n) => app.findSensitiveData(`c=${n}`).find((f) => f.kind === 'Card number')?.note;
    expect(net('4111111111111111')).toBe('Visa');
    expect(net('5555555555554444')).toBe('Mastercard');
    expect(net('378282246310005')).toBe('Amex');
    expect(net('6011111111111117')).toBe('Discover');
  });
});

describe('findSensitiveData — personal data', () => {
  it('finds an email address', () => {
    expect(values('to=efe.ziza%40example.com&x=1'.replace('%40', '@'), 'Email'))
      .toContain('efe.ziza@example.com');
  });

  /// IBANs carry a mod-97 checksum, which is what separates one from an
  /// order reference that happens to start with two letters.
  it('accepts only checksum-valid IBANs', () => {
    expect(values('iban=GB82WEST12345698765432', 'IBAN')).toEqual(['GB82WEST12345698765432']);
    expect(values('iban=GB82WEST12345698765433', 'IBAN')).toEqual([]);
    expect(values('ref=AB12ORDER00000000001234', 'IBAN')).toEqual([]);
  });
});

describe('findSensitiveData — hygiene', () => {
  it('reports each distinct value once', () => {
    const text = 'password=hunter2&confirm_password=hunter2&password=hunter2';
    expect(values(text, 'Credential')).toEqual(['hunter2']);
  });

  it('returns nothing for ordinary traffic', () => {
    expect(app.findSensitiveData('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'))
      .toEqual([]);
  });

  it('handles empty and absent input', () => {
    expect(app.findSensitiveData('')).toEqual([]);
    expect(app.findSensitiveData(null)).toEqual([]);
  });
});

describe('collectLeaks', () => {
  const pkt = (text, over = {}) => ({
    raw: [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
      0x45, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
      0, 80, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0,
      ...[...text].map((c) => c.charCodeAt(0)),
    ],
    protocol: 'HTTP',
    dst_addr: '10.0.0.2',
    dst_host: 'shop.example',
    ...over,
  });

  /// A session cookie rides on every request. One row per packet would bury
  /// the twelve things that matter under nine hundred repeats of one of them.
  it('collapses a repeated value into one row with a count', () => {
    const leaks = app.collectLeaks([
      pkt('POST /login\r\n\r\npassword=hunter2'),
      pkt('POST /login\r\n\r\npassword=hunter2'),
      pkt('POST /login\r\n\r\npassword=hunter2'),
    ]);

    expect(leaks).toHaveLength(1);
    expect(leaks[0].count).toBe(3);
    expect(leaks[0].packet).toBe(1); // first sighting, so it can be jumped to
  });

  it('records where each value was seen', () => {
    const [leak] = app.collectLeaks([pkt('POST /x\r\n\r\npassword=hunter2')]);
    expect(leak.host).toBe('shop.example');
    expect(leak.protocol).toBe('HTTP');
  });

  /// A leaked API key and an email address in a query string are different
  /// orders of problem, and the list has to open with the worse one.
  it('ranks secrets above personal data', () => {
    const leaks = app.collectLeaks([
      pkt('GET /?contact=efe@example.com'),
      pkt('GET /?token=AKIAIOSFODNN7EXAMPLE'),
    ]);
    expect(leaks[0].kind).toBe('API key');
    expect(leaks[leaks.length - 1].kind).toBe('Email');
  });

  /// "Where did it get this?" has to be answerable from the panel. The context
  /// shows the surrounding request text, and the byte range points the hex
  /// dump at the value itself rather than just naming the packet.
  it('records the surrounding text and the byte range of each finding', () => {
    const body = 'POST /pay HTTP/1.1\r\nHost: shop\r\n\r\namount=10&card=4111111111111111&cvv=1';
    const [leak] = app.collectLeaks([pkt(body)]);

    expect(leak.context).toContain('card=');
    expect(leak.byteStart).toBeGreaterThan(0);
    expect(leak.byteEnd - leak.byteStart).toBe(16);
  });

  /// The offset is into the frame, not the payload — the hex dump shows the
  /// whole frame, so an offset measured from the payload would land 54 bytes
  /// early, inside the headers.
  it('reports the byte range relative to the frame', () => {
    const body = 'x=4111111111111111';
    const [leak] = app.collectLeaks([pkt(body)]);
    const raw = pkt(body).raw;
    const digits = String.fromCharCode(...raw.slice(leak.byteStart, leak.byteEnd));

    expect(digits).toBe('4111111111111111');
  });

  it('ignores packets with no payload', () => {
    expect(app.collectLeaks([{ raw: [], protocol: 'TCP' }])).toEqual([]);
    expect(app.collectLeaks([])).toEqual([]);
  });
});

describe('maskSecret', () => {
  /// The panel defaults to masked because a capture is often reviewed on a
  /// shared screen — showing a full card number to fix a leak would be one.
  it('leaves only the last four digits of a card', () => {
    expect(app.maskSecret('Card number', '4111111111111111')).toBe('••••••••••••1111');
  });

  it('keeps an email recognisable without spelling it out', () => {
    expect(app.maskSecret('Email', 'efe@example.com')).toBe('ef•@example.com');
  });

  it('shows both ends of a long secret so it can be identified', () => {
    const masked = app.maskSecret('API key', 'AKIAIOSFODNN7EXAMPLE');
    expect(masked.startsWith('AKIA')).toBe(true);
    expect(masked.endsWith('MPLE')).toBe(true);
    expect(masked).not.toContain('IOSFODNN7EXA');
  });

  it('reveals nothing at all of a short one', () => {
    expect(app.maskSecret('Credential', 'hunter2')).toBe('•••••••');
  });
});
