import { describe, it, expect } from 'bun:test';
import { generateRecoveryCodes, verifyRecoveryCode } from '../totp/recovery';
import { createHash } from '../hash';

const hash = createHash({ rounds: 4 }); // low rounds for fast tests

describe('generateRecoveryCodes', () => {
  it('returns 8 codes by default', async () => {
    const { codes } = await generateRecoveryCodes(hash);
    expect(codes).toHaveLength(8);
  });

  it('returns the specified count', async () => {
    const { codes } = await generateRecoveryCodes(hash, 12);
    expect(codes).toHaveLength(12);
  });

  it('codes match xxxxxxxx-xxxxxxxx format', async () => {
    const { codes } = await generateRecoveryCodes(hash);
    for (const code of codes) {
      expect(code).toMatch(/^[a-f0-9]{8}-[a-f0-9]{8}$/);
    }
  });

  it('generates unique codes', async () => {
    const { codes } = await generateRecoveryCodes(hash);
    const unique = new Set(codes);
    expect(unique.size).toBe(codes.length);
  });

  it('returns hashed versions alongside plain codes', async () => {
    const { codes, hashed } = await generateRecoveryCodes(hash, 2);
    expect(hashed).toHaveLength(2);
    for (const h of hashed) {
      expect(h).not.toBe(codes[0]);
      expect(h).not.toBe(codes[1]);
      expect(typeof h).toBe('string');
    }
  });
});

describe('verifyRecoveryCode', () => {
  it('returns valid: true and removes the used code from remaining', async () => {
    const { codes, hashed } = await generateRecoveryCodes(hash, 3);

    const result = await verifyRecoveryCode(codes[1], hashed, hash);
    expect(result.valid).toBe(true);
    expect(result.remaining).toHaveLength(2);
  });

  it('returns valid: false for an invalid code', async () => {
    const { hashed } = await generateRecoveryCodes(hash, 3);

    const result = await verifyRecoveryCode('xxxx-yyyy', hashed, hash);
    expect(result.valid).toBe(false);
    expect(result.remaining).toHaveLength(3);
  });

  it('remaining hashes can still verify other codes', async () => {
    const { codes, hashed } = await generateRecoveryCodes(hash, 3);

    // Use code 0
    const first = await verifyRecoveryCode(codes[0], hashed, hash);
    expect(first.valid).toBe(true);

    // Use code 2 with updated remaining
    const second = await verifyRecoveryCode(codes[2], first.remaining, hash);
    expect(second.valid).toBe(true);
    expect(second.remaining).toHaveLength(1);
  });
});
