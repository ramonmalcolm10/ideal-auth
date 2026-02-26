import { createHmac } from 'node:crypto';
import { timingSafeEqual } from './timing-safe';

export function signData(data: string, secret: string): string {
  if (!secret) throw new Error('secret must not be empty');
  return createHmac('sha256', secret).update(data).digest('hex');
}

export function verifySignature(
  data: string,
  signature: string,
  secret: string,
): boolean {
  const expected = signData(data, secret);
  return timingSafeEqual(expected, signature);
}
