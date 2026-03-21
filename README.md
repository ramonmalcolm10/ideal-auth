# ideal-auth

Auth primitives for the JS ecosystem. Zero framework dependencies. Inspired by Laravel's `Auth` and `Hash` facades.

**[Documentation](https://ramonmalcolm10.github.io/ideal-auth/)**

Provide a cookie bridge (3 functions) once during setup, and `auth().login(user)` just works — handles session creation, cookie encryption, and storage internally via [iron-session](https://github.com/vvo/iron-session).

## Install

```bash
bun add ideal-auth
```

## Generate Secrets

```bash
# Session secret (required — used by createAuth)
bunx ideal-auth secret
# IDEAL_AUTH_SECRET=aLThikMgJKMBB5WZLE-lCaOQUdgPWU8BHRv99bkYaVY

# Encryption key (optional — used by encrypt/decrypt for data at rest)
bunx ideal-auth encryption-key
# ENCRYPTION_KEY=9546dd9fa461ce15f0aacd6e1b461b52
```

Copy the output into your `.env` file. `IDEAL_AUTH_SECRET` must be at least 32 characters. `ENCRYPTION_KEY` is only needed if you use `encrypt()`/`decrypt()` (e.g., encrypting TOTP secrets or access tokens at rest).

## Quick Start

```typescript
// lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { cookies } from 'next/headers';
import { db } from '@/lib/db';

export const hash = createHash({ rounds: 12 });

export const auth = createAuth({
  secret: process.env.IDEAL_AUTH_SECRET!, // 32+ characters

  cookie: {
    get: async (name) => (await cookies()).get(name)?.value,
    set: async (name, value, opts) => (await cookies()).set(name, value, opts),
    delete: async (name) => (await cookies()).delete(name),
  },

  hash,

  resolveUser: async (id) => {
    return db.user.findUnique({ where: { id } });
  },

  resolveUserByCredentials: async (credentials) => {
    return db.user.findUnique({ where: { email: credentials.email } });
  },
});
```

```typescript
// Server Action
'use server';
import { auth } from '@/lib/auth';

// Call auth() once per request and reuse the instance — it caches the
// session payload and user, so subsequent calls avoid redundant work.
const session = auth();

// Login with credentials (password verified automatically)
const success = await session.attempt({ email, password });

// Login with a user object directly
await session.login(user);

// Login by user ID
await session.loginById('user-123');

// Check session
const isLoggedIn = await session.check();
const currentUser = await session.user();
const userId = await session.id();

// Logout
await session.logout();
```

## API

### `createAuth(config)`

Returns a function `auth()` that creates an `AuthInstance` on each call.

#### Config

| Field | Type | Required | Default |
| --- | --- | --- | --- |
| `secret` | `string` | Yes | — |
| `cookie` | `CookieBridge` | Yes | — |
| `resolveUser` | `(id: string) => Promise<User \| null \| undefined>` | Yes (unless `sessionFields` is provided) | — |
| `sessionFields` | `(keyof User & string)[]` | Yes (unless `resolveUser` is provided) | — |
| `hash` | `HashInstance` | No | — |
| `resolveUserByCredentials` | `(creds: Record<string, any>) => Promise<User \| null \| undefined>` | No | — |
| `credentialKey` | `string` | No | `'password'` |
| `passwordField` | `string` | No | `'password'` |
| `attemptUser` | `(creds: Record<string, any>) => Promise<User \| null \| undefined>` | No | — |
| `session.cookieName` | `string` | No | `'ideal_session'` |
| `session.maxAge` | `number` (seconds) | No | `604800` (7 days) |
| `session.rememberMaxAge` | `number` (seconds) | No | `2592000` (30 days) |
| `session.cookie` | `Partial<ConfigurableCookieOptions>` | No | secure in prod, sameSite lax, path / (`httpOnly` is always `true` — not configurable) |

#### AuthInstance Methods

| Method | Returns | Description |
| --- | --- | --- |
| `login(user, options?)` | `Promise<void>` | Set session cookie for the given user |
| `loginById(id, options?)` | `Promise<void>` | Resolve user by ID, then set session cookie |
| `attempt(credentials, options?)` | `Promise<boolean>` | Find user, verify password, login if valid |
| `logout()` | `Promise<void>` | Delete session cookie |
| `check()` | `Promise<boolean>` | Is the session valid? |
| `user()` | `Promise<User \| null>` | Get the authenticated user |
| `id()` | `Promise<string \| null>` | Get the authenticated user's ID |

All login methods accept an optional `LoginOptions` object:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `remember` | `boolean` | `undefined` | `true`: use `rememberMaxAge` (30 days). `false`: session cookie (expires when browser closes). Omitted: use default `maxAge` (7 days). |

```typescript
const session = auth();

// Remember me — 30-day persistent cookie
await session.attempt({ email, password }, { remember: true });

// No remember — session cookie, expires when browser closes
await session.login(user, { remember: false });

// Default — 7-day cookie
await session.login(user);
```

#### `attempt()` — Two Modes

**Laravel-style (recommended):** Provide `hash` and `resolveUserByCredentials` in config. `attempt()` strips the credential key (default `password`) from the credentials, looks up the user with the remaining fields, and calls `hash.verify()` against the stored hash automatically.

```typescript
const auth = createAuth({
  // ...
  hash,
  resolveUserByCredentials: async (creds) => {
    return db.user.findUnique({ where: { email: creds.email } });
  },
});

const session = auth();
await session.attempt({ email, password }); // password verified internally
```

**Manual (escape hatch):** Provide `attemptUser` for full control over lookup and verification. Takes precedence over the Laravel-style config if both are provided.

```typescript
const auth = createAuth({
  // ...
  attemptUser: async (creds) => {
    const user = await db.user.findUnique({ where: { email: creds.email } });
    if (!user) return null;
    if (!(await hash.verify(creds.password, user.password))) return null;
    return user;
  },
});
```

---

### `createHash(config?)`

Returns a `HashInstance` using bcrypt. Requires `bcryptjs` (optional peer dependency):

```bash
bun add bcryptjs
```

| Option | Type | Default |
| --- | --- | --- |
| `rounds` | `number` | `12` |

```typescript
import { createHash } from 'ideal-auth';

const hash = createHash({ rounds: 12 });

const hashed = await hash.make('password');
const valid  = await hash.verify('password', hashed); // true
```

### Custom hash (bring your own)

Skip `bcryptjs` entirely by providing your own `HashInstance`:

```typescript
import { prehash } from 'ideal-auth';
import type { HashInstance } from 'ideal-auth';

// Bun native bcrypt (use prehash to prevent silent truncation at 72 bytes)
const hash: HashInstance = {
  make: (password) => Bun.password.hash(prehash(password), { algorithm: 'bcrypt', cost: 12 }),
  verify: (password, hash) => Bun.password.verify(prehash(password), hash),
};

// Bun argon2id (OWASP recommended — no prehash needed, no input length limit)
const hash: HashInstance = {
  make: (password) => Bun.password.hash(password, { algorithm: 'argon2id' }),
  verify: (password, hash) => Bun.password.verify(password, hash),
};
```

---

### Crypto Utilities

Standalone functions for tokens, signing, and encryption. No framework dependencies — uses `node:crypto`.

#### `generateToken(bytes?)`

Generate a cryptographically secure random hex string.

```typescript
import { generateToken } from 'ideal-auth';

const token = generateToken();     // 64 hex chars (32 bytes)
const short = generateToken(16);   // 32 hex chars (16 bytes)
```

#### `signData(data, secret)` / `verifySignature(data, signature, secret)`

HMAC-SHA256 signing with timing-safe comparison.

```typescript
import { signData, verifySignature } from 'ideal-auth';

const sig = signData('user:123:reset', secret);
const valid = verifySignature('user:123:reset', sig, secret); // true
```

#### `encrypt(plaintext, secret)` / `decrypt(ciphertext, secret)`

AES-256-GCM encryption with scrypt key derivation. Output is base64url-encoded.

```typescript
import { encrypt, decrypt } from 'ideal-auth';

const encrypted = await encrypt('sensitive data', secret);
const decrypted = await decrypt(encrypted, secret); // 'sensitive data'
```

#### `timingSafeEqual(a, b)`

Constant-time string comparison to prevent timing attacks.

```typescript
import { timingSafeEqual } from 'ideal-auth';

timingSafeEqual('abc', 'abc'); // true
timingSafeEqual('abc', 'xyz'); // false
```

---

### `createTokenVerifier(config)`

Signed, expiring tokens for password resets, email verification, magic links, invites — any flow that needs a one-time, time-limited token tied to a user. Create one instance per use case with its own secret/expiry. You handle delivery (email, SMS) — ideal-auth handles the token lifecycle.

#### Config

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `secret` | `string` | — | Secret for HMAC signing (required) |
| `expiryMs` | `number` | `3600000` (1 hour) | Token lifetime in milliseconds |

#### Password Reset

```typescript
import { createTokenVerifier, createHash } from 'ideal-auth';

const passwordReset = createTokenVerifier({
  secret: process.env.IDEAL_AUTH_SECRET! + '-reset',
  expiryMs: 60 * 60 * 1000, // 1 hour
});

// Forgot password — generate token, send it via email (POST body, not URL query)
const token = passwordReset.createToken(user.id);
await sendEmail(user.email, `https://example.com/reset/${token}`);

// Reset password — verify token
const result = passwordReset.verifyToken(token);
if (!result) throw new Error('Invalid or expired token');

// IMPORTANT: Invalidate the token by checking iatMs against the user's last
// password change. Tokens are stateless — without this check, a token remains
// valid until expiry even after the password is changed.
if (result.iatMs < user.passwordChangedAt) throw new Error('Token already used');

// result.userId is now available — update the password
const hash = createHash();
await db.user.update({
  where: { id: result.userId },
  data: { password: await hash.make(newPassword), passwordChangedAt: Date.now() },
});
```

#### Email Verification

```typescript
import { createTokenVerifier } from 'ideal-auth';

const emailVerification = createTokenVerifier({
  secret: process.env.IDEAL_AUTH_SECRET! + '-email',
  expiryMs: 24 * 60 * 60 * 1000, // 24 hours
});

// After registration — generate token, send verification email
const token = emailVerification.createToken(user.id);
await sendEmail(user.email, `https://example.com/verify/${token}`);

// Verify — validate token from the URL
const result = emailVerification.verifyToken(token);
if (!result) throw new Error('Invalid or expired token');

// Mark user as verified
await db.user.update({
  where: { id: result.userId },
  data: { emailVerifiedAt: new Date() },
});
```

Use different secrets (or suffixes) per use case so tokens aren't interchangeable between flows.

**Token invalidation:** Tokens are stateless and valid until expiry. `verifyToken()` returns `iatMs` (issued-at timestamp in milliseconds) so you can reject tokens issued before a relevant event (e.g. password change, email already verified). You must implement this check — the library does not track token usage.

---

### Two-Factor Authentication (TOTP)

`createTOTP()` provides TOTP (RFC 6238) generation and verification — no framework dependencies.

#### Setup Flow

```typescript
import { createTOTP } from 'ideal-auth';

const totp = createTOTP();

// 1. Generate a secret for the user
const secret = totp.generateSecret();
// Store `secret` in your database (encrypted) for the user

// 2. Generate a QR code URI for the user to scan
const uri = totp.generateQrUri({
  secret,
  issuer: 'MyApp',
  account: user.email,
});
// Render `uri` as a QR code (use any QR library)

// 3. Verify the first code to confirm setup
const valid = totp.verify(codeFromUser, secret);
if (valid) {
  // Mark 2FA as enabled for the user
}
```

#### Login Verification

```typescript
const totp = createTOTP();

// After password login, prompt for TOTP code
const valid = totp.verify(codeFromUser, user.totpSecret);
if (!valid) {
  throw new Error('Invalid 2FA code');
}
```

**Replay protection:** A valid TOTP code can be verified multiple times within the acceptance window (default 90 seconds). For mission-critical apps, store the last used time step per user and reject codes at or before that step.

#### Config

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `digits` | `number` | `6` | Number of digits in the code |
| `period` | `number` | `30` | Time step in seconds |
| `window` | `number` | `1` | Window of ±N steps to account for clock drift |

#### Recovery Codes

Generate backup codes for users who lose access to their authenticator app.

```typescript
import { generateRecoveryCodes, verifyRecoveryCode, createHash } from 'ideal-auth';

const hash = createHash();

// Generate codes — returns plain codes to show the user AND hashed codes to store
const { codes, hashed } = await generateRecoveryCodes(hash);
// Show `codes` to the user once, store `hashed` in the database

// Verify a recovery code during login
const { valid, remaining } = await verifyRecoveryCode(code, user.hashedRecoveryCodes, hash);
if (valid) {
  // Update stored hashes to `remaining` (removes the used code)
  await db.user.update({ where: { id: user.id }, data: { recoveryCodes: remaining } });
}
```

---

### Rate Limiting

In-memory rate limiter. Provide a custom `RateLimitStore` for Redis/DB-backed limiting.

```typescript
import { createRateLimiter } from 'ideal-auth';

const limiter = createRateLimiter({
  maxAttempts: 5,
  windowMs: 60_000, // 1 minute
});

const result = await limiter.attempt('login:user@example.com');
// { allowed: true, remaining: 4, resetAt: Date }

// Reset after successful login
await limiter.reset('login:user@example.com');
```

#### Full Login Action Example (Next.js)

```typescript
'use server';

import { redirect } from 'next/navigation';
import { headers } from 'next/headers';
import { auth } from '@/lib/auth';
import { createRateLimiter } from 'ideal-auth';

const limiter = createRateLimiter({
  maxAttempts: 5,
  windowMs: 60_000,
});

export async function loginAction(formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  // NOTE: x-forwarded-for is only trustworthy behind a reverse proxy you
  // control (e.g. Vercel, Cloudflare, nginx). Without one, it's spoofable.
  const headerStore = await headers();
  const ip = headerStore.get('x-forwarded-for') ?? '127.0.0.1';
  const key = `login:${ip}`;

  const { allowed, remaining, resetAt } = await limiter.attempt(key);

  if (!allowed) {
    const seconds = Math.ceil((resetAt.getTime() - Date.now()) / 1000);
    redirect(`/?error=rate_limit&retry=${seconds}`);
  }

  const session = auth();
  const success = await session.attempt({ email, password });

  if (!success) {
    redirect(`/?error=invalid&remaining=${remaining}`);
  }

  await limiter.reset(key);
  redirect('/');
}
```

#### Custom Store

Implement the `RateLimitStore` interface for persistent storage:

```typescript
import { createRateLimiter, type RateLimitStore } from 'ideal-auth';

class RedisRateLimitStore implements RateLimitStore {
  async increment(key: string, windowMs: number) {
    // Redis INCR + PEXPIRE logic
    return { count, resetAt };
  }
  async reset(key: string) {
    // Redis DEL
  }
}

const limiter = createRateLimiter({
  maxAttempts: 5,
  windowMs: 60_000,
  store: new RedisRateLimitStore(),
});
```

---

## How It Works

Sessions are **stateless, encrypted cookies** powered by iron-session (AES-256-CBC + HMAC integrity).

1. **`login(user)`** — Creates a `SessionPayload { uid, iat, exp }`, seals it with iron-session, writes the encrypted string to the cookie via the bridge.
2. **`check()` / `user()` / `id()`** — Reads the cookie via the bridge, unseals the payload, checks expiry. `user()` additionally calls `resolveUser(id)` to fetch the full user.
3. **`logout()`** — Deletes the cookie via the bridge.

No session IDs. No server-side storage. The encrypted cookie *is* the session.

---

## Cookie Bridge

The bridge decouples ideal-auth from any framework. Three functions:

```typescript
interface CookieBridge {
  get(name: string): Promise<string | undefined> | string | undefined;
  set(name: string, value: string, options: CookieOptions): Promise<void> | void;
  delete(name: string): Promise<void> | void;
}
```

**Next.js** (App Router):

```typescript
import { cookies } from 'next/headers';

cookie: {
  get: async (name) => (await cookies()).get(name)?.value,
  set: async (name, value, opts) => (await cookies()).set(name, value, opts),
  delete: async (name) => (await cookies()).delete(name),
}
```

**Express / Hono / any framework** — adapt to your framework's cookie API.

---

## Dependencies

| Package | Purpose | Required |
| --- | --- | --- |
| `iron-session` | Session sealing/unsealing (AES-256-CBC + HMAC) | Yes |
| `bcryptjs` | Password hashing (used by `createHash()`) | Optional — not needed if you provide your own `HashInstance` |

Zero framework imports. Works in Node, Bun, Deno, and edge runtimes.

## Claude Code

If you use [Claude Code](https://claude.com/claude-code), install the ideal-auth plugin so your AI assistant knows the full API, cookie bridge patterns, security best practices, and implementation guides:

```bash
claude plugin install github:ramonmalcolm10/ideal-auth
```

After installing, Claude Code will automatically help with auth setup, login/registration flows, middleware, 2FA, password reset, rate limiting, and more — using the correct patterns for your framework.

---

## Support

If this saved you time, consider supporting the project:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?logo=buy-me-a-coffee&logoColor=white)](https://buymeacoffee.com/ramonmalcolm)

## License

[MIT](./LICENSE.md)