import { randomBytes } from 'node:crypto';

export function generateToken(bytes: number = 32): string {
  if (bytes < 1) throw new Error('bytes must be at least 1');
  return randomBytes(bytes).toString('hex');
}
