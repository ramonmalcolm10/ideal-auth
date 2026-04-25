import { generateToken } from '../crypto/token';
import { signData, verifySignature } from '../crypto/hmac';
import type { TokenVerifierConfig, TokenVerifierInstance } from '../types';

const DEFAULT_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

function validateSecret(secret: string | undefined): asserts secret is string {
  if (!secret || secret.length < 32) {
    throw new Error('secret must be at least 32 characters');
  }
}

export function createTokenVerifier(
  config: TokenVerifierConfig,
): TokenVerifierInstance {
  const expiryMs = config.expiryMs ?? DEFAULT_EXPIRY_MS;

  return {
    createToken(userId: string): string {
      validateSecret(config.secret);
      const encodedUserId = Buffer.from(userId, 'utf8').toString('base64url');
      const id = generateToken(20);
      const iat = Date.now();
      const exp = iat + expiryMs;
      const payload = `${encodedUserId}.${id}.${iat}.${exp}`;
      const signature = signData(payload, config.secret);
      return `${payload}.${signature}`;
    },

    verifyToken(token: string): { userId: string; iatMs: number } | null {
      if (!config.secret || config.secret.length < 32) return null;
      const parts = token.split('.');
      if (parts.length !== 5) return null;

      const [encodedUserId, id, iatStr, expStr, signature] = parts;
      const payload = `${encodedUserId}.${id}.${iatStr}.${expStr}`;

      if (!verifySignature(payload, signature, config.secret)) return null;

      const exp = Number(expStr);
      const iat = Number(iatStr);
      if (Number.isNaN(exp) || Number.isNaN(iat) || Date.now() >= exp) return null;

      const userId = Buffer.from(encodedUserId, 'base64url').toString('utf8');
      return { userId, iatMs: iat };
    },
  };
}
