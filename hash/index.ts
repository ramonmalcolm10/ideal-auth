import { createHash as nodeCryptoHash } from 'node:crypto';
import type { HashInstance, HashConfig } from '../types';

const DEFAULT_ROUNDS = 12;
const BCRYPT_MAX_BYTES = 72;

/**
 * SHA-256 prehash for bcrypt's 72-byte input limit.
 * Passwords exceeding 72 UTF-8 bytes are hashed to a 44-char base64 string
 * before being passed to bcrypt, preventing silent truncation.
 *
 * Only needed for bcrypt — argon2 has no input length limit.
 * Applied automatically by `createHash()`. Use this when building
 * a custom bcrypt `HashInstance` (e.g., with `Bun.password`).
 */
export function prehash(password: string): string {
  if (Buffer.byteLength(password, 'utf8') <= BCRYPT_MAX_BYTES) return password;
  return nodeCryptoHash('sha256').update(password).digest('base64');
}

async function loadBcrypt() {
  try {
    return await import('bcryptjs');
  } catch {
    throw new Error(
      'bcryptjs is required for createHash(). Install it as a dependency in your project.\n' +
      'Alternatively, provide your own HashInstance (e.g., using Bun.password or argon2).',
    );
  }
}

export function createHash(config?: HashConfig): HashInstance {
  const rounds = config?.rounds ?? DEFAULT_ROUNDS;
  let bcryptModule: typeof import('bcryptjs') | null = null;

  async function getBcrypt() {
    if (!bcryptModule) {
      bcryptModule = await loadBcrypt();
    }
    return bcryptModule;
  }

  return {
    async make(password: string): Promise<string> {
      if (!password) throw new Error('password must not be empty');
      const bcrypt = await getBcrypt();
      const salt = await bcrypt.genSalt(rounds);
      return bcrypt.hash(prehash(password), salt);
    },

    async verify(password: string, hash: string): Promise<boolean> {
      const bcrypt = await getBcrypt();
      return bcrypt.compare(prehash(password), hash);
    },
  };
}
