// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { loadApp, tcpFrame } from './load-app.js';

const app = loadApp();

/** A TLS record: content type, version, length, then body. */
function record(type, body, { major = 0x03, minor = 0x03, len = null } = {}) {
  const declared = len === null ? body.length : len;
  return tcpFrame([type, major, minor, (declared >> 8) & 0xff, declared & 0xff, ...body]);
}

/** A handshake record carrying message type `msg`. */
function handshake(msg, extra = 8) {
  // 1 byte message type + 3 byte length + filler, as on the wire.
  return record(22, [msg, 0x00, 0x00, extra, ...new Array(extra).fill(0)]);
}

describe('tlsRecordLabel', () => {
  /// The reason the function exists: a TLS negotiation labelled by TCP flags
  /// is a column of identical "PSH ACK" rows, and the shape of the handshake —
  /// the thing worth looking at — is invisible.
  it('names each handshake message', () => {
    const expected = {
      1: 'ClientHello',
      2: 'ServerHello',
      11: 'Certificate',
      12: 'ServerKeyExchange',
      14: 'ServerHelloDone',
      16: 'ClientKeyExchange',
      20: 'Finished',
      4: 'NewSessionTicket',
      8: 'EncryptedExtensions',
    };
    for (const [msg, name] of Object.entries(expected)) {
      expect(app.tlsRecordLabel(handshake(Number(msg)))).toBe(name);
    }
  });

  it('names the non-handshake record types', () => {
    expect(app.tlsRecordLabel(record(20, [0x01]))).toBe('ChangeCipherSpec');
    expect(app.tlsRecordLabel(record(21, [0x02, 0x28]))).toBe('Alert');
    expect(app.tlsRecordLabel(record(23, [0xde, 0xad, 0xbe, 0xef]))).toBe('AppData');
  });

  /// TLS 1.3 encrypts everything after ServerHello inside application-data
  /// records, so "AppData" is the honest answer — the message type is under
  /// the encryption and guessing it would be invention.
  it('reports an encrypted handshake as application data', () => {
    expect(app.tlsRecordLabel(record(23, new Array(64).fill(0xa5)))).toBe('AppData');
  });

  /// An unrecognised handshake type still gets the layer right rather than
  /// falling back to TCP flags.
  it('falls back to the record type for an unknown message', () => {
    expect(app.tlsRecordLabel(handshake(99))).toBe('Handshake');
  });

  describe('does not claim traffic that is not TLS', () => {
    it('rejects a plain HTTP request', () => {
      const http = [...'GET / HTTP/1.1\r\nHost: x\r\n\r\n'].map((c) => c.charCodeAt(0));
      expect(app.tlsRecordLabel(tcpFrame(http))).toBeNull();
    });

    it('rejects an all-zero payload', () => {
      expect(app.tlsRecordLabel(tcpFrame(new Array(64).fill(0)))).toBeNull();
    });

    /// The version field is the cheapest discriminator: three bytes of the
    /// right shape are common in binary protocols, a 0x03 major is not.
    it('rejects an implausible record version', () => {
      expect(app.tlsRecordLabel(handshakeWithVersion(0x05, 0x03))).toBeNull();
      expect(app.tlsRecordLabel(handshakeWithVersion(0x03, 0x09))).toBeNull();
    });

    /// A length that could not fit a TLS record is the other tell.
    it('rejects an out-of-range record length', () => {
      expect(app.tlsRecordLabel(record(22, [1, 0, 0, 0], { len: 0 }))).toBeNull();
      expect(app.tlsRecordLabel(record(22, [1, 0, 0, 0], { len: 40000 }))).toBeNull();
    });

    it('rejects a payload too short to hold a record header', () => {
      expect(app.tlsRecordLabel(tcpFrame([22, 3, 3]))).toBeNull();
      expect(app.tlsRecordLabel(tcpFrame([]))).toBeNull();
    });
  });
});

function handshakeWithVersion(major, minor) {
  return record(22, [1, 0, 0, 4, 0, 0, 0, 0], { major, minor });
}
