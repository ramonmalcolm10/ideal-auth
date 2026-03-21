import { describe, it, expect } from 'bun:test';
import * as idealAuth from '..';

describe('public API exports', () => {
  const expectedExports = [
    'createAuth',
    'createHash',
    'prehash',
    'generateToken',
    'signData',
    'verifySignature',
    'encrypt',
    'decrypt',
    'timingSafeEqual',
    'createTokenVerifier',
    'createRateLimiter',
    'MemoryRateLimitStore',
    'createTOTP',
    'generateRecoveryCodes',
    'verifyRecoveryCode',
  ];

  for (const name of expectedExports) {
    it(`exports ${name}`, () => {
      expect((idealAuth as any)[name]).toBeDefined();
    });
  }
});
