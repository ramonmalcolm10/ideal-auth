// Auth
export { createAuth } from './auth';

// Hash
export { createHash, prehash } from './hash';

// Crypto utilities
export { generateToken } from './crypto/token';
export { signData, verifySignature } from './crypto/hmac';
export { encrypt, decrypt } from './crypto/encryption';
export { timingSafeEqual } from './crypto/timing-safe';

// Token verification (password reset, email verification, etc.)
export { createTokenVerifier } from './token-verifier';

// Rate limiting
export { createRateLimiter } from './rate-limit';
export { MemoryRateLimitStore } from './rate-limit/memory-store';

// TOTP (Two-Factor Authentication)
export { createTOTP } from './totp';
export { generateRecoveryCodes, verifyRecoveryCode } from './totp/recovery';

// Types
export type {
  AnyUser,
  CookieBridge,
  ConfigurableCookieOptions,
  CookieOptions,
  SessionPayload,
  AuthConfig,
  HashConfig,
  LoginOptions,
  AuthInstance,
  HashInstance,
  TokenVerifierConfig,
  TokenVerifierInstance,
  RateLimitStore,
  RateLimiterConfig,
  RateLimitResult,
  TOTPConfig,
  TOTPInstance,
  RecoveryCodeResult,
} from './types';
