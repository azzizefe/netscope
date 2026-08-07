// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
import { describe, it, expect } from 'vitest';
import { mergeIdentity, identityLabel } from '../frontend/modules/fingerprint.js';

describe('fingerprint identity merging and labeling', () => {
  it('initializes identity with fingerprint fields', () => {
    const fp = { name: 'My-MacBook', deviceType: 'MacBook', os: 'macOS', model: 'MacBookPro18,1' };
    const id = mergeIdentity(null, fp);
    expect(id.name).toBe('My-MacBook');
    expect(id.deviceType).toBe('MacBook');
    expect(id.os).toBe('macOS');
    expect(id.model).toBe('MacBookPro18,1');
  });

  it('keeps stronger identity when merging subsequent fingerprints', () => {
    const id = { name: 'Old-Name', deviceType: 'MacBook', os: null, _weakOs: true };
    const fp = { deviceType: 'Generic Device', os: 'macOS 14' };
    mergeIdentity(id, fp);
    expect(id.name).toBe('Old-Name');
    expect(id.deviceType).toBe('MacBook');
    expect(id.os).toBe('macOS 14');
  });

  it('generates a clean identity label', () => {
    expect(identityLabel({ deviceType: 'iPhone', os: 'iOS 17' })).toBe('iPhone');
    expect(identityLabel({ deviceType: 'Printer', os: 'Embedded' })).toBe('Printer');
    expect(identityLabel(null)).toBeNull();
  });
});
