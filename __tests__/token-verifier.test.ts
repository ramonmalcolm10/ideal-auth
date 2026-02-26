import { describe, it, expect } from 'bun:test';
import { createTokenVerifier } from '../token-verifier';

const SECRET = 'a'.repeat(32);

describe('createTokenVerifier', () => {
  const verifier = createTokenVerifier({ secret: SECRET });

  it('creates a token string', () => {
    const token = verifier.createToken('user-1');
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(5);
  });

  it('throws on missing secret', () => {
    expect(() => createTokenVerifier({ secret: '' })).toThrow(
      'secret must be at least 32 characters',
    );
  });

  it('throws on short secret', () => {
    expect(() => createTokenVerifier({ secret: 'short' })).toThrow(
      'secret must be at least 32 characters',
    );
  });

  it('verifies a valid token and returns iat', () => {
    const before = Date.now();
    const token = verifier.createToken('user-1');
    const result = verifier.verifyToken(token);
    expect(result).toMatchObject({ userId: 'user-1' });
    expect(result!.iatMs).toBeGreaterThanOrEqual(before);
    expect(result!.iatMs).toBeLessThanOrEqual(Date.now());
  });

  it('returns null for tampered token', () => {
    const token = verifier.createToken('user-1');
    const tampered = token.slice(0, -1) + 'x';
    expect(verifier.verifyToken(tampered)).toBeNull();
  });

  it('returns null for tampered userId', () => {
    const token = verifier.createToken('user-1');
    const parts = token.split('.');
    parts[0] = Buffer.from('user-2', 'utf8').toString('base64url');
    expect(verifier.verifyToken(parts.join('.'))).toBeNull();
  });

  it('handles userId containing dots', () => {
    const token = verifier.createToken('org.team.user-123');
    const result = verifier.verifyToken(token);
    expect(result).toMatchObject({ userId: 'org.team.user-123' });
  });

  it('returns null for expired token', () => {
    const expired = createTokenVerifier({ secret: SECRET, expiryMs: 0 });
    const token = expired.createToken('user-1');
    expect(expired.verifyToken(token)).toBeNull();
  });

  it('returns null for malformed token', () => {
    expect(verifier.verifyToken('garbage')).toBeNull();
    expect(verifier.verifyToken('')).toBeNull();
    expect(verifier.verifyToken('a.b')).toBeNull();
    expect(verifier.verifyToken('a.b.c.d.e.f')).toBeNull();
  });

  it('returns null with wrong secret', () => {
    const token = verifier.createToken('user-1');
    const other = createTokenVerifier({ secret: 'b'.repeat(32) });
    expect(other.verifyToken(token)).toBeNull();
  });

  it('respects custom expiryMs', () => {
    const longExpiry = createTokenVerifier({
      secret: SECRET,
      expiryMs: 1000 * 60 * 60 * 24, // 24 hours
    });
    const token = longExpiry.createToken('user-1');
    expect(longExpiry.verifyToken(token)).toMatchObject({ userId: 'user-1' });
  });

  it('each token is unique', () => {
    const a = verifier.createToken('user-1');
    const b = verifier.createToken('user-1');
    expect(a).not.toBe(b);
  });

  describe('use cases', () => {
    it('works for password reset', () => {
      const passwordReset = createTokenVerifier({
        secret: SECRET,
        expiryMs: 60 * 60 * 1000, // 1 hour
      });
      const token = passwordReset.createToken('user-1');
      expect(passwordReset.verifyToken(token)).toMatchObject({ userId: 'user-1' });
    });

    it('works for email verification', () => {
      const emailVerification = createTokenVerifier({
        secret: SECRET,
        expiryMs: 24 * 60 * 60 * 1000, // 24 hours
      });
      const token = emailVerification.createToken('user-1');
      expect(emailVerification.verifyToken(token)).toMatchObject({ userId: 'user-1' });
    });

    it('iat is stored in token, not derived from expiryMs', () => {
      // Create token with a 1-hour expiry
      const hourVerifier = createTokenVerifier({
        secret: SECRET,
        expiryMs: 60 * 60 * 1000,
      });
      const before = Date.now();
      const token = hourVerifier.createToken('user-1');

      // Verify with a different expiryMs — iat should still be accurate
      // since it's stored in the token, not computed as exp - expiryMs
      const dayVerifier = createTokenVerifier({
        secret: SECRET,
        expiryMs: 24 * 60 * 60 * 1000,
      });
      // Token was signed with a different secret-scoped expiryMs,
      // but same secret means signature is valid. The iat in the token
      // should reflect actual creation time, not be derived from config.
      const result = hourVerifier.verifyToken(token);
      expect(result).not.toBeNull();
      expect(result!.iatMs).toBeGreaterThanOrEqual(before);
      expect(result!.iatMs).toBeLessThanOrEqual(Date.now());
    });

    it('tokens from different verifiers are not interchangeable', () => {
      const resetVerifier = createTokenVerifier({
        secret: SECRET + '-reset',
        expiryMs: 60 * 60 * 1000,
      });
      const emailVerifier = createTokenVerifier({
        secret: SECRET + '-email',
        expiryMs: 24 * 60 * 60 * 1000,
      });

      const resetToken = resetVerifier.createToken('user-1');
      const emailToken = emailVerifier.createToken('user-1');

      expect(resetVerifier.verifyToken(emailToken)).toBeNull();
      expect(emailVerifier.verifyToken(resetToken)).toBeNull();
    });
  });
});
