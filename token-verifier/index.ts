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
  // Structural config error — always known at definition time, so throw
  // eagerly (unlike the secret, which may only be bound at request time).
  if (!config.purpose || typeof config.purpose !== 'string') {
    throw new Error(
      "purpose is required — e.g. createTokenVerifier({ secret, purpose: 'password-reset' }). " +
        'It binds tokens to one flow so they cannot be replayed in another.',
    );
  }
  const expiryMs = config.expiryMs ?? DEFAULT_EXPIRY_MS;

  // Purpose binding: the purpose is mixed into the signed payload (never the
  // token itself), so a token minted for one purpose fails verification on a
  // verifier configured with a different one — even when they share a secret.
  // '\0' cannot appear in the dot-joined payload, so the binding is unambiguous.
  function signedPayload(payload: string): string {
    return `${payload}\0${config.purpose}`;
  }

  return {
    createToken(userId: string): string {
      validateSecret(config.secret);
      const encodedUserId = Buffer.from(userId, 'utf8').toString('base64url');
      const id = generateToken(20);
      const iat = Date.now();
      const exp = iat + expiryMs;
      const payload = `${encodedUserId}.${id}.${iat}.${exp}`;
      const signature = signData(signedPayload(payload), config.secret);
      return `${payload}.${signature}`;
    },

    verifyToken(token: string): { userId: string; iatMs: number } | null {
      if (!config.secret || config.secret.length < 32) return null;
      const parts = token.split('.');
      if (parts.length !== 5) return null;

      const [encodedUserId, id, iatStr, expStr, signature] = parts;
      const payload = `${encodedUserId}.${id}.${iatStr}.${expStr}`;

      if (!verifySignature(signedPayload(payload), signature, config.secret)) return null;

      const exp = Number(expStr);
      const iat = Number(iatStr);
      if (Number.isNaN(exp) || Number.isNaN(iat) || Date.now() >= exp) return null;

      const userId = Buffer.from(encodedUserId, 'base64url').toString('utf8');
      return { userId, iatMs: iat };
    },
  };
}
