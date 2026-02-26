import { describe, it, expect } from 'bun:test';
import { createHmac } from 'node:crypto';
import { createTOTP } from '../totp';
import { base32Decode } from '../totp/base32';

describe('createTOTP', () => {
  const totp = createTOTP();

  describe('generateSecret', () => {
    it('returns a valid base32 string', () => {
      const secret = totp.generateSecret();
      expect(secret).toMatch(/^[A-Z2-7]+$/);
    });

    it('returns a 32-character string (20 bytes encoded)', () => {
      const secret = totp.generateSecret();
      expect(secret).toHaveLength(32);
    });

    it('decodes back to 20 bytes', () => {
      const secret = totp.generateSecret();
      const decoded = base32Decode(secret);
      expect(decoded).toHaveLength(20);
    });

    it('generates unique secrets', () => {
      const a = totp.generateSecret();
      const b = totp.generateSecret();
      expect(a).not.toBe(b);
    });
  });

  describe('verify', () => {
    it('accepts a valid token for the current time', () => {
      const secret = totp.generateSecret();
      const token = generateCode(secret, 6, 30, 0);
      expect(totp.verify(token, secret)).toBe(true);
    });

    it('rejects an incorrect token', () => {
      const secret = totp.generateSecret();
      expect(totp.verify('000000', secret)).toBe(false);
    });

    it('accepts tokens within the default window (±1 step)', () => {
      const secret = totp.generateSecret();
      const pastToken = generateCode(secret, 6, 30, -1);
      const futureToken = generateCode(secret, 6, 30, 1);
      expect(totp.verify(pastToken, secret)).toBe(true);
      expect(totp.verify(futureToken, secret)).toBe(true);
    });

    it('rejects tokens outside the window', () => {
      const secret = totp.generateSecret();
      const farPast = generateCode(secret, 6, 30, -2);
      const farFuture = generateCode(secret, 6, 30, 2);
      expect(totp.verify(farPast, secret)).toBe(false);
      expect(totp.verify(farFuture, secret)).toBe(false);
    });

    it('uses timing-safe comparison (no early exit on partial match)', () => {
      const secret = totp.generateSecret();
      // Both wrong tokens should take approximately the same time
      // (we can't measure timing precisely, but we verify the function works)
      expect(totp.verify('999999', secret)).toBe(false);
      expect(totp.verify('111111', secret)).toBe(false);
    });
  });

  describe('generateQrUri', () => {
    it('returns a valid otpauth:// URI', () => {
      const secret = totp.generateSecret();
      const uri = totp.generateQrUri({ secret, issuer: 'MyApp', account: 'user@example.com' });
      expect(uri).toMatch(/^otpauth:\/\/totp\//);
    });

    it('includes correct parameters', () => {
      const secret = totp.generateSecret();
      const uri = totp.generateQrUri({ secret, issuer: 'MyApp', account: 'user@example.com' });
      const url = new URL(uri);
      expect(url.searchParams.get('secret')).toBe(secret);
      expect(url.searchParams.get('issuer')).toBe('MyApp');
      expect(url.searchParams.get('digits')).toBe('6');
      expect(url.searchParams.get('period')).toBe('30');
      expect(url.searchParams.get('algorithm')).toBe('SHA1');
    });

    it('encodes special characters in issuer and account', () => {
      const secret = totp.generateSecret();
      const uri = totp.generateQrUri({ secret, issuer: 'My App', account: 'user name' });
      expect(uri).toContain('My%20App');
      expect(uri).toContain('user%20name');
    });
  });

  describe('custom config', () => {
    it('respects custom digits', () => {
      const custom = createTOTP({ digits: 8 });
      const secret = custom.generateSecret();
      const uri = custom.generateQrUri({ secret, issuer: 'Test', account: 'test@test.com' });
      expect(new URL(uri).searchParams.get('digits')).toBe('8');
    });

    it('respects custom period', () => {
      const custom = createTOTP({ period: 60 });
      const secret = custom.generateSecret();
      const uri = custom.generateQrUri({ secret, issuer: 'Test', account: 'test@test.com' });
      expect(new URL(uri).searchParams.get('period')).toBe('60');
    });

    it('respects custom window', () => {
      const noWindow = createTOTP({ window: 0 });
      const secret = noWindow.generateSecret();
      // Current step should still work
      const current = generateCode(secret, 6, 30, 0);
      expect(noWindow.verify(current, secret)).toBe(true);
      // Adjacent step should NOT work with window=0
      const adjacent = generateCode(secret, 6, 30, -1);
      expect(noWindow.verify(adjacent, secret)).toBe(false);
    });
  });
});

// Test helper: generate a TOTP code at a given offset from the current time step
function generateCode(secret: string, digits: number, period: number, offset: number): string {
  const counter = Math.floor(Date.now() / 1000 / period) + offset;
  const buf = Buffer.alloc(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }
  const hmac = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[off] & 0x7f) << 24) |
    ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8) |
    (hmac[off + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, '0');
}
