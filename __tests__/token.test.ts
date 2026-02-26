import { describe, it, expect } from 'bun:test';
import { generateToken } from '../crypto/token';

describe('generateToken', () => {
  it('default: returns 64-char hex string (32 bytes)', () => {
    const token = generateToken();
    expect(token).toHaveLength(64);
  });

  it('custom bytes: length = 2 * bytes', () => {
    const token = generateToken(16);
    expect(token).toHaveLength(32);
  });

  it('multiple calls produce different tokens', () => {
    const a = generateToken();
    const b = generateToken();
    expect(a).not.toBe(b);
  });

  it('output is valid hex', () => {
    const token = generateToken();
    expect(token).toMatch(/^[0-9a-f]+$/);
  });
});
