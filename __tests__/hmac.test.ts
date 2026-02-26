import { describe, it, expect } from 'bun:test';
import { signData, verifySignature } from '../crypto/hmac';

const SECRET = 'test-secret-key';

describe('signData', () => {
  it('returns consistent signature for same input+secret', () => {
    const sig1 = signData('hello', SECRET);
    const sig2 = signData('hello', SECRET);
    expect(sig1).toBe(sig2);
  });

  it('different secrets produce different signatures', () => {
    const sig1 = signData('hello', 'secret-a');
    const sig2 = signData('hello', 'secret-b');
    expect(sig1).not.toBe(sig2);
  });

  it('throws on empty secret', () => {
    expect(() => signData('hello', '')).toThrow('secret must not be empty');
  });
});

describe('verifySignature', () => {
  it('returns true for valid signature', () => {
    const sig = signData('hello', SECRET);
    expect(verifySignature('hello', sig, SECRET)).toBe(true);
  });

  it('returns false for wrong signature', () => {
    const sig = signData('hello', SECRET);
    const wrongSig = sig.slice(0, -4) + 'ffff';
    expect(verifySignature('hello', wrongSig, SECRET)).toBe(false);
  });

  it('returns false for wrong secret', () => {
    const sig = signData('hello', SECRET);
    expect(verifySignature('hello', sig, 'wrong-secret')).toBe(false);
  });

  it('returns false for tampered data', () => {
    const sig = signData('hello', SECRET);
    expect(verifySignature('tampered', sig, SECRET)).toBe(false);
  });
});
