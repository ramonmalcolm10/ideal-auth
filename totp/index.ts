import { createHmac, randomBytes } from 'node:crypto';
import { timingSafeEqual } from '../crypto/timing-safe';
import { base32Encode, base32Decode } from './base32';
import type { TOTPConfig, TOTPInstance } from '../types';

function generate(secret: string, digits: number, period: number, counter?: number): string {
  const time = counter ?? Math.floor(Date.now() / 1000 / period);
  const buf = Buffer.alloc(8);
  let tmp = time;
  for (let i = 7; i >= 0; i--) {
    buf[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  const hmac = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(code % 10 ** digits).padStart(digits, '0');
}

export function createTOTP(config?: TOTPConfig): TOTPInstance {
  const digits = config?.digits ?? 6;
  const period = config?.period ?? 30;
  const window = config?.window ?? 1;

  return {
    generateSecret(): string {
      return base32Encode(randomBytes(20));
    },

    generateQrUri(options: { secret: string; issuer: string; account: string }): string {
      const { secret, issuer, account } = options;
      const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
      const params = new URLSearchParams({
        secret,
        issuer,
        algorithm: 'SHA1',
        digits: String(digits),
        period: String(period),
      });
      return `otpauth://totp/${label}?${params.toString()}`;
    },

    verify(token: string, secret: string): boolean {
      const counter = Math.floor(Date.now() / 1000 / period);
      for (let i = -window; i <= window; i++) {
        const candidate = generate(secret, digits, period, counter + i);
        if (timingSafeEqual(token, candidate)) return true;
      }
      return false;
    },
  };
}
