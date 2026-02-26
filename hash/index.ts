import { createHash as nodeCryptoHash } from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { HashInstance, HashConfig } from '../types';

const DEFAULT_ROUNDS = 12;
const BCRYPT_MAX_BYTES = 72;

function prehash(password: string): string {
  return nodeCryptoHash('sha256').update(password).digest('base64');
}

export function createHash(config?: HashConfig): HashInstance {
  const rounds = config?.rounds ?? DEFAULT_ROUNDS;

  return {
    async make(password: string): Promise<string> {
      if (!password) throw new Error('password must not be empty');
      const input = Buffer.byteLength(password, 'utf8') > BCRYPT_MAX_BYTES ? prehash(password) : password;
      const salt = await bcrypt.genSalt(rounds);
      return bcrypt.hash(input, salt);
    },

    async verify(password: string, hash: string): Promise<boolean> {
      const input = Buffer.byteLength(password, 'utf8') > BCRYPT_MAX_BYTES ? prehash(password) : password;
      return bcrypt.compare(input, hash);
    },
  };
}
