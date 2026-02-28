---
trigger: auth, login, logout, session, register, signup, sign up, sign in, sign out, password, 2FA, two-factor, totp, mfa, ideal-auth, cookie bridge, middleware, route protection, rate limit, rate limiting, password reset, forgot password, email verification, remember me, recovery code, csrf, encrypt, decrypt, hash, bcrypt, token, secret, session cookie
---

You are an expert on `ideal-auth`, the auth primitives library for the JS ecosystem. You have complete knowledge of its API, patterns, security model, and framework integrations. Use this knowledge to help users implement authentication correctly.

When the user asks to "set up auth" or "add authentication" in a project that has `ideal-auth` installed, use the AskUserQuestion tool to detect their setup:

```
questions:
  - question: "Which framework are you using?"
    header: "Framework"
    options:
      - label: "Next.js (App Router)"
        description: "React framework with Server Actions and middleware"
      - label: "SvelteKit"
        description: "Svelte framework with form actions and hooks"
      - label: "Express"
        description: "Node.js HTTP framework"
      - label: "Hono"
        description: "Lightweight framework for Node, Bun, Deno, Workers"
    multiSelect: false

  - question: "Which auth features do you need?"
    header: "Features"
    options:
      - label: "Login + Registration"
        description: "Email/password auth with session management"
      - label: "Password Reset"
        description: "Forgot password flow with email tokens"
      - label: "Two-Factor Auth (TOTP)"
        description: "Authenticator app + recovery codes"
      - label: "Rate Limiting"
        description: "Brute-force protection on login"
    multiSelect: true
```

Additional framework options to offer if the user picks "Other": Nuxt, TanStack Start, Elysia.

---

# ideal-auth Complete Reference

## Overview

Auth primitives for the JS ecosystem. Zero framework dependencies. Inspired by Laravel's `Auth` and `Hash` facades.

- **Sessions**: Stateless, encrypted cookies via iron-session (AES-256-CBC + HMAC integrity)
- **Passwords**: bcrypt via bcryptjs with SHA-256 prehash for passwords > 72 bytes
- **Tokens**: HMAC-SHA256 signed, expiring tokens for password reset, email verification, magic links
- **TOTP**: RFC 6238 two-factor authentication with recovery codes
- **Rate Limiting**: Pluggable store (in-memory default, Redis/DB for production)
- **Crypto**: AES-256-GCM encryption, HMAC signing, timing-safe comparison
- **Cookie Bridge**: 3-function adapter — works with any framework

Install: `bun add ideal-auth` (or `npm install ideal-auth`)

Generate secret: `bunx ideal-auth secret` (outputs `IDEAL_AUTH_SECRET=...` for `.env`)

Generate encryption key: `bunx ideal-auth encryption-key` (for encrypting TOTP secrets at rest)

---

## API Reference

### `createAuth(config): () => AuthInstance`

Returns a factory function. Call `auth()` per request to get an `AuthInstance` scoped to that request's cookies. The instance caches the session payload and user — call it once per request and reuse.

#### AuthConfig

```typescript
type AuthConfig<TUser extends AnyUser> = {
  secret: string;                    // 32+ chars, required — throws if shorter
  cookie: CookieBridge;              // required
  resolveUser: (id: string) => Promise<TUser | null>;  // required

  // Session options
  session?: {
    cookieName?: string;             // default: 'ideal_session'
    maxAge?: number;                 // default: 604800 (7 days, in seconds)
    rememberMaxAge?: number;         // default: 2592000 (30 days, in seconds)
    cookie?: Partial<ConfigurableCookieOptions>;
  };

  // Laravel-style attempt (recommended)
  hash?: HashInstance;
  resolveUserByCredentials?: (credentials: Record<string, any>) => Promise<TUser | null>;
  credentialKey?: string;            // default: 'password'
  passwordField?: string;            // default: 'password'

  // Manual attempt (escape hatch — takes precedence if both provided)
  attemptUser?: (credentials: Record<string, any>) => Promise<TUser | null>;
};
```

#### AuthInstance Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login(user, options?)` | `Promise<void>` | Set session cookie for the given user |
| `loginById(id, options?)` | `Promise<void>` | Resolve user by ID, then set session cookie |
| `attempt(credentials, options?)` | `Promise<boolean>` | Find user, verify password, login if valid |
| `logout()` | `Promise<void>` | Delete session cookie |
| `check()` | `Promise<boolean>` | Is the session valid? (fast, cached) |
| `user()` | `Promise<TUser \| null>` | Get the authenticated user |
| `id()` | `Promise<string \| null>` | Get the authenticated user's ID |

#### LoginOptions

```typescript
type LoginOptions = {
  remember?: boolean;
  // true:      use rememberMaxAge (30 days)
  // false:     session cookie (expires when browser closes)
  // undefined: use default maxAge (7 days)
};
```

#### `attempt()` — Two Modes

**Laravel-style (recommended):** Provide `hash` and `resolveUserByCredentials`. The `attempt()` method strips the credential key (default `'password'`) from credentials, looks up the user with remaining fields, and verifies the hash automatically.

```typescript
const auth = createAuth({
  secret: process.env.IDEAL_AUTH_SECRET!,
  cookie: createCookieBridge(),
  hash,
  resolveUser: async (id) => db.user.findUnique({ where: { id } }),
  resolveUserByCredentials: async (creds) => {
    // creds = { email: '...' } — password already stripped
    return db.user.findUnique({ where: { email: creds.email } });
  },
});
```

**Manual (escape hatch):** Provide `attemptUser` for full control over lookup and verification. Takes precedence if both are provided.

```typescript
const auth = createAuth({
  secret: process.env.IDEAL_AUTH_SECRET!,
  cookie: createCookieBridge(),
  resolveUser: async (id) => db.user.findUnique({ where: { id } }),
  attemptUser: async (creds) => {
    const user = await db.user.findUnique({ where: { email: creds.email } });
    if (!user) return null;
    if (!(await hash.verify(creds.password, user.password))) return null;
    return user;
  },
});
```

---

### `createHash(config?): HashInstance`

bcrypt password hashing with automatic SHA-256 prehash for passwords > 72 bytes.

```typescript
type HashConfig = { rounds?: number };  // default: 12

type HashInstance = {
  make(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
};
```

```typescript
import { createHash } from 'ideal-auth';

const hash = createHash({ rounds: 12 });
const hashed = await hash.make('password');
const valid = await hash.verify('password', hashed); // true
```

---

### `createTokenVerifier(config): TokenVerifierInstance`

Signed, expiring tokens for password resets, email verification, magic links, invites. Create one instance per use case with its own secret/expiry.

```typescript
type TokenVerifierConfig = {
  secret: string;      // 32+ chars, required
  expiryMs?: number;   // default: 3600000 (1 hour)
};

type TokenVerifierInstance = {
  createToken(userId: string): string;
  verifyToken(token: string): { userId: string; iatMs: number } | null;
};
```

Token format: `encodedUserId.randomId.issuedAtMs.expiryMs.signature` (HMAC-SHA256 signed).

**Important:** Tokens are stateless. Use `iatMs` to reject tokens issued before a relevant event (e.g., password change). Use different secrets per use case so tokens aren't interchangeable.

---

### `createTOTP(config?): TOTPInstance`

RFC 6238 TOTP generation and verification.

```typescript
type TOTPConfig = {
  digits?: number;   // default: 6
  period?: number;   // default: 30 (seconds)
  window?: number;   // default: 1 (±1 time step, ~90 second acceptance window)
};

type TOTPInstance = {
  generateSecret(): string;                              // 32-char base32 string
  generateQrUri(opts: { secret: string; issuer: string; account: string }): string;
  verify(token: string, secret: string): boolean;
};
```

---

### `generateRecoveryCodes(hash, count?): Promise<{ codes, hashed }>`

Generate backup codes for 2FA recovery. Returns plaintext codes (show once to user) and bcrypt-hashed codes (store in DB).

```typescript
import { generateRecoveryCodes, verifyRecoveryCode, createHash } from 'ideal-auth';

const hash = createHash();
const { codes, hashed } = await generateRecoveryCodes(hash, 8);
// codes: string[] — show to user once (format: XXXXXXXX-XXXXXXXX)
// hashed: string[] — store in database

const { valid, remaining } = await verifyRecoveryCode(code, storedHashes, hash);
// valid: boolean
// remaining: string[] — update DB with this (removes used code)
```

---

### `createRateLimiter(config): RateLimiterInstance`

```typescript
type RateLimiterConfig = {
  maxAttempts: number;       // required
  windowMs: number;          // required
  store?: RateLimitStore;    // default: MemoryRateLimitStore
};

type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
};

// Methods: attempt(key): Promise<RateLimitResult>, reset(key): Promise<void>
```

**MemoryRateLimitStore** characteristics: max 10,000 entries, 1-minute cleanup interval, resets on process restart, single-process only. **Use a persistent store (Redis/DB) in production.**

Custom store interface:

```typescript
interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<{ count: number; resetAt: Date }>;
  reset(key: string): Promise<void>;
}
```

---

### Crypto Utilities

All use `node:crypto` — no third-party dependencies.

```typescript
import {
  generateToken,
  signData,
  verifySignature,
  encrypt,
  decrypt,
  timingSafeEqual,
} from 'ideal-auth';

// Random hex token (default 32 bytes = 64 hex chars)
const token = generateToken();
const short = generateToken(16);  // 32 hex chars

// HMAC-SHA256 signing
const sig = signData('user:123:reset', secret);
const valid = verifySignature('user:123:reset', sig, secret);

// AES-256-GCM encryption (scrypt key derivation, base64url output)
const encrypted = await encrypt('sensitive data', secret);
const decrypted = await decrypt(encrypted, secret);

// Constant-time string comparison
timingSafeEqual('abc', 'abc'); // true
```

---

### Key Types

```typescript
type AnyUser = { id: string | number; [key: string]: any };

type CookieBridge = {
  get(name: string): Promise<string | undefined> | string | undefined;
  set(name: string, value: string, options: CookieOptions): Promise<void> | void;
  delete(name: string): Promise<void> | void;
};

type CookieOptions = {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  maxAge?: number;
  expires?: Date;
  domain?: string;
};

// httpOnly is always forced to true — not configurable
type ConfigurableCookieOptions = Omit<CookieOptions, 'httpOnly'>;

type SessionPayload = {
  uid: string;   // user ID (always string)
  iat: number;   // issued-at (Unix seconds)
  exp: number;   // expiration (Unix seconds)
};
```

---

## Cookie Bridge Patterns

### Next.js (App Router)

```typescript
// lib/cookies.ts
import { cookies } from 'next/headers';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(): CookieBridge {
  return {
    async get(name: string) {
      const cookieStore = await cookies();
      return cookieStore.get(name)?.value;
    },
    async set(name, value, options) {
      const cookieStore = await cookies();
      cookieStore.set(name, value, options);
    },
    async delete(name) {
      const cookieStore = await cookies();
      cookieStore.delete(name);
    },
  };
}
```

**IMPORTANT:** `cookies()` is async in Next.js 15+. If on Next.js 14, remove the `await`.

Auth setup:

```typescript
// lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';
import { db } from './db';

type User = {
  id: string;
  email: string;
  name: string;
  password: string;
};

const hash = createHash({ rounds: 12 });

const auth = createAuth<User>({
  secret: process.env.IDEAL_AUTH_SECRET!,
  cookie: createCookieBridge(),
  hash,

  async resolveUser(id) {
    return db.user.findUnique({ where: { id } });
  },

  async resolveUserByCredentials(credentials) {
    return db.user.findUnique({
      where: { email: credentials.email },
    });
  },
});

export { auth, hash };
```

**`createAuth` returns a factory function.** Call `auth()` inside each Server Action. Do not call at module level.

Login action:

```typescript
// app/actions/login.ts
'use server';

import { redirect } from 'next/navigation';
import { auth } from '@/lib/auth';

export async function loginAction(_prev: unknown, formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;
  const remember = formData.get('remember') === 'on';

  if (!email || !password) {
    return { error: 'Email and password are required.' };
  }

  const session = auth();
  const success = await session.attempt(
    { email, password },
    { remember },
  );

  if (!success) {
    return { error: 'Invalid email or password.' };
  }

  redirect('/dashboard');
}
```

Login form:

```tsx
// app/login/page.tsx
'use client';

import { useActionState } from 'react';
import { loginAction } from '@/app/actions/login';

export default function LoginPage() {
  const [state, formAction, pending] = useActionState(loginAction, null);

  return (
    <form action={formAction}>
      {state?.error && <p className="text-red-500">{state.error}</p>}

      <label htmlFor="email">Email</label>
      <input id="email" name="email" type="email" required />

      <label htmlFor="password">Password</label>
      <input id="password" name="password" type="password" required />

      <label>
        <input name="remember" type="checkbox" /> Remember me
      </label>

      <button type="submit" disabled={pending}>
        {pending ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  );
}
```

Registration action:

```typescript
// app/actions/register.ts
'use server';

import { redirect } from 'next/navigation';
import { auth, hash } from '@/lib/auth';
import { db } from '@/lib/db';

export async function registerAction(_prev: unknown, formData: FormData) {
  const email = formData.get('email') as string;
  const name = formData.get('name') as string;
  const password = formData.get('password') as string;
  const passwordConfirmation = formData.get('password_confirmation') as string;

  if (!email || !name || !password) {
    return { error: 'All fields are required.' };
  }

  if (password.length < 8) {
    return { error: 'Password must be at least 8 characters.' };
  }

  if (password !== passwordConfirmation) {
    return { error: 'Passwords do not match.' };
  }

  const existing = await db.user.findUnique({ where: { email } });
  if (existing) {
    return { error: 'An account with this email already exists.' };
  }

  const user = await db.user.create({
    data: {
      email,
      name,
      password: await hash.make(password),
    },
  });

  const session = auth();
  await session.login(user);

  redirect('/dashboard');
}
```

Logout action:

```typescript
// app/actions/logout.ts
'use server';

import { redirect } from 'next/navigation';
import { auth } from '@/lib/auth';

export async function logoutAction() {
  const session = auth();
  await session.logout();
  redirect('/login');
}
```

Middleware (route protection):

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const protectedRoutes = ['/dashboard', '/settings', '/profile'];
const authRoutes = ['/login', '/register'];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const hasSession = request.cookies.has('ideal_session');

  if (protectedRoutes.some((route) => pathname.startsWith(route))) {
    if (!hasSession) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('callbackUrl', pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  if (authRoutes.some((route) => pathname.startsWith(route))) {
    if (hasSession) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/settings/:path*', '/profile/:path*', '/login', '/register'],
};
```

**Note:** Next.js middleware runs on Edge Runtime. `auth()` requires Node.js runtime (iron-session uses Node crypto). The middleware checks cookie existence as a fast first pass; actual cryptographic verification happens server-side via `auth().check()` or `auth().user()`.

Server-side auth guard helper:

```typescript
// lib/auth-guard.ts
import { redirect } from 'next/navigation';
import { auth } from '@/lib/auth';

export async function requireAuth() {
  const session = auth();
  const user = await session.user();

  if (!user) {
    redirect('/login');
  }

  return user;
}
```

Getting the current user in a Server Component:

```tsx
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function DashboardPage() {
  const session = auth();
  const user = await session.user();

  if (!user) redirect('/login');

  return <h1>Welcome, {user.name}</h1>;
}
```

Pass user data to Client Components as props — only pass serializable, non-sensitive fields.

**CSRF:** Next.js Server Actions have built-in CSRF protection (Origin header validation). For API Route Handlers, validate the Origin header manually:

```typescript
// app/api/example/route.ts
import { headers } from 'next/headers';
import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const headerStore = await headers();
  const origin = headerStore.get('origin');
  const host = headerStore.get('host');

  if (!origin || new URL(origin).host !== host) {
    return NextResponse.json({ error: 'Invalid origin' }, { status: 403 });
  }

  // ... handle request
}
```

**Edge Runtime:** Use `export const runtime = 'nodejs'` in any Route Handler that calls `auth()`.

---

### SvelteKit

```typescript
// src/lib/server/cookies.ts
import type { Cookies } from '@sveltejs/kit';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(cookies: Cookies): CookieBridge {
  return {
    get(name: string) {
      return cookies.get(name);
    },
    set(name, value, options) {
      cookies.set(name, value, {
        ...options,
        path: options.path ?? '/',
      });
    },
    delete(name) {
      cookies.delete(name, { path: '/' });
    },
  };
}
```

SvelteKit requires an explicit `path` on `cookies.set()`.

Auth setup:

```typescript
// src/lib/server/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';
import { db } from '$lib/server/db';
import { IDEAL_AUTH_SECRET } from '$env/static/private';

type User = { id: string; email: string; name: string; password: string };

export const hash = createHash({ rounds: 12 });

export function auth(cookies: import('@sveltejs/kit').Cookies) {
  const authFactory = createAuth<User>({
    secret: IDEAL_AUTH_SECRET,
    cookie: createCookieBridge(cookies),
    hash,

    async resolveUser(id) {
      return db.user.findUnique({ where: { id } });
    },

    async resolveUserByCredentials(credentials) {
      return db.user.findUnique({ where: { email: credentials.email } });
    },
  });

  return authFactory();
}
```

Pass `cookies` from the `RequestEvent` each time — keeps requests isolated.

Login (form action):

```typescript
// src/routes/login/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ cookies }) => {
  const session = auth(cookies);
  if (await session.check()) redirect(303, '/dashboard');
};

export const actions: Actions = {
  default: async ({ request, cookies }) => {
    const data = await request.formData();
    const email = data.get('email') as string;
    const password = data.get('password') as string;
    const remember = data.get('remember') === 'on';

    if (!email || !password) {
      return fail(400, { error: 'Email and password are required.', email });
    }

    const session = auth(cookies);
    const success = await session.attempt({ email, password }, { remember });

    if (!success) {
      return fail(400, { error: 'Invalid email or password.', email });
    }

    redirect(303, '/dashboard');
  },
};
```

Registration (form action):

```typescript
// src/routes/register/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { auth, hash } from '$lib/server/auth';
import { db } from '$lib/server/db';
import type { Actions } from './$types';

export const actions: Actions = {
  default: async ({ request, cookies }) => {
    const data = await request.formData();
    const email = data.get('email') as string;
    const name = data.get('name') as string;
    const password = data.get('password') as string;
    const passwordConfirmation = data.get('password_confirmation') as string;

    if (!email || !name || !password) {
      return fail(400, { error: 'All fields are required.', email, name });
    }

    if (password.length < 8) {
      return fail(400, { error: 'Password must be at least 8 characters.', email, name });
    }

    if (password !== passwordConfirmation) {
      return fail(400, { error: 'Passwords do not match.', email, name });
    }

    const existing = await db.user.findUnique({ where: { email } });
    if (existing) {
      return fail(400, { error: 'An account with this email already exists.', email, name });
    }

    const user = await db.user.create({
      data: { email, name, password: await hash.make(password) },
    });

    const session = auth(cookies);
    await session.login(user);

    redirect(303, '/dashboard');
  },
};
```

Auth guard (handle hook):

```typescript
// src/hooks.server.ts
import { redirect, type Handle } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';

const protectedRoutes = ['/dashboard', '/settings', '/profile'];
const authRoutes = ['/login', '/register'];

export const handle: Handle = async ({ event, resolve }) => {
  const session = auth(event.cookies);
  const user = await session.user();

  event.locals.user = user
    ? { id: user.id, email: user.email, name: user.name }
    : null;

  const { pathname } = event.url;

  if (protectedRoutes.some((route) => pathname.startsWith(route))) {
    if (!user) redirect(303, `/login?callbackUrl=${encodeURIComponent(pathname)}`);
  }

  if (authRoutes.some((route) => pathname.startsWith(route))) {
    if (user) redirect(303, '/dashboard');
  }

  return resolve(event);
};
```

Declare types in `src/app.d.ts`:

```typescript
declare global {
  namespace App {
    interface Locals {
      user: { id: string; email: string; name: string } | null;
    }
  }
}

export {};
```

**CSRF:** SvelteKit has built-in CSRF protection — auto-validates Origin header on all form submissions. Do not set `checkOrigin: false` in production.

---

### Express

Requires `cookie-parser`: `bun add cookie-parser` + `bun add -D @types/cookie-parser @types/express`

```typescript
// src/lib/cookies.ts
import type { Request, Response } from 'express';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(req: Request, res: Response): CookieBridge {
  return {
    get(name: string) {
      return req.cookies[name];
    },
    set(name, value, options) {
      res.cookie(name, value, {
        httpOnly: options.httpOnly,
        secure: options.secure,
        sameSite: options.sameSite,
        path: options.path ?? '/',
        ...(options.maxAge !== undefined && { maxAge: options.maxAge * 1000 }),
      });
    },
    delete(name) {
      res.clearCookie(name, { path: '/' });
    },
  };
}
```

**IMPORTANT:** Express `res.cookie()` uses milliseconds for `maxAge`, but ideal-auth provides seconds. The bridge multiplies by 1000.

Auth setup:

```typescript
// src/lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';
import { db } from './db';

type User = { id: string; email: string; name: string; password: string };

export const hash = createHash({ rounds: 12 });

export function auth(req: import('express').Request, res: import('express').Response) {
  const authFactory = createAuth<User>({
    secret: process.env.IDEAL_AUTH_SECRET!,
    cookie: createCookieBridge(req, res),
    hash,

    async resolveUser(id) {
      return db.user.findUnique({ where: { id } });
    },

    async resolveUserByCredentials(credentials) {
      return db.user.findUnique({ where: { email: credentials.email } });
    },
  });

  return authFactory();
}
```

App setup:

```typescript
// src/app.ts
import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csrfProtection); // see CSRF section below
```

Auth middleware:

```typescript
// src/middleware/auth.ts
import type { Request, Response, NextFunction } from 'express';
import { auth } from '../lib/auth';

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const session = auth(req, res);
  const user = await session.user();

  if (!user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  req.user = user;
  next();
}
```

Extend Express Request type:

```typescript
// src/types/express.d.ts
declare global {
  namespace Express {
    interface Request {
      user?: { id: string; email: string; name: string };
    }
  }
}

export {};
```

**CSRF:** Express has NO built-in CSRF protection. Implement Origin header validation:

```typescript
// src/middleware/csrf.ts
import type { Request, Response, NextFunction } from 'express';

const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  if (SAFE_METHODS.includes(req.method)) return next();

  const origin = req.get('origin');
  const host = req.get('host');

  if (!origin || !host) {
    return res.status(403).json({ error: 'Forbidden: missing origin header.' });
  }

  try {
    if (new URL(origin).host !== host) {
      return res.status(403).json({ error: 'Forbidden: origin mismatch.' });
    }
  } catch {
    return res.status(403).json({ error: 'Forbidden: invalid origin.' });
  }

  next();
}
```

For HTML forms, use a CSRF token approach with `generateToken` and `timingSafeEqual` from ideal-auth.

---

### Hono

```typescript
// src/lib/cookies.ts
import type { Context } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(c: Context): CookieBridge {
  return {
    get(name: string) {
      return getCookie(c, name);
    },
    set(name, value, options) {
      setCookie(c, name, value, {
        httpOnly: options.httpOnly,
        secure: options.secure,
        sameSite: options.sameSite === 'lax' ? 'Lax' : options.sameSite === 'strict' ? 'Strict' : 'None',
        path: options.path ?? '/',
        ...(options.maxAge !== undefined && { maxAge: options.maxAge }),
      });
    },
    delete(name) {
      deleteCookie(c, name, { path: '/' });
    },
  };
}
```

**Note:** Hono expects capitalized `sameSite` values (`'Lax'`, `'Strict'`, `'None'`). The bridge converts.

Auth setup:

```typescript
// src/lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';
import { db } from './db';

type User = { id: string; email: string; name: string; password: string };

export const hash = createHash({ rounds: 12 });

export function auth(c: import('hono').Context) {
  const authFactory = createAuth<User>({
    secret: c.env?.IDEAL_AUTH_SECRET ?? process.env.IDEAL_AUTH_SECRET!,
    cookie: createCookieBridge(c),
    hash,

    async resolveUser(id) {
      return db.user.findUnique({ where: { id } });
    },

    async resolveUserByCredentials(credentials) {
      return db.user.findUnique({ where: { email: credentials.email } });
    },
  });

  return authFactory();
}
```

Auth middleware:

```typescript
// src/middleware/auth.ts
import { createMiddleware } from 'hono/factory';
import { auth } from '../lib/auth';

type Env = {
  Variables: { user: { id: string; email: string; name: string } };
};

export const requireAuth = createMiddleware<Env>(async (c, next) => {
  const session = auth(c);
  const user = await session.user();

  if (!user) return c.json({ error: 'Authentication required.' }, 401);

  c.set('user', { id: user.id, email: user.email, name: user.name });
  await next();
});
```

**CSRF:** Hono has built-in `csrf()` middleware:

```typescript
import { csrf } from 'hono/csrf';
app.use(csrf());
```

**Cloudflare Workers:** Add `nodejs_compat` compatibility flag to `wrangler.toml`. Access env via `c.env.IDEAL_AUTH_SECRET`.

---

### Nuxt

```typescript
// server/utils/cookies.ts
import type { H3Event } from 'h3';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(event: H3Event): CookieBridge {
  return {
    get(name: string) {
      return getCookie(event, name);
    },
    set(name, value, options) {
      setCookie(event, name, value, options);
    },
    delete(name) {
      deleteCookie(event, name, { path: '/' });
    },
  };
}
```

`getCookie`, `setCookie`, `deleteCookie` are auto-imported from `h3` in Nuxt server routes.

Auth setup:

```typescript
// server/utils/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';

type User = { id: string; email: string; name: string; password: string };

export const hash = createHash({ rounds: 12 });

export function auth(event: H3Event) {
  const config = useRuntimeConfig();

  const authFactory = createAuth<User>({
    secret: config.idealAuthSecret,
    cookie: createCookieBridge(event),
    hash,

    async resolveUser(id) {
      return db.user.findUnique({ where: { id } });
    },

    async resolveUserByCredentials(credentials) {
      return db.user.findUnique({ where: { email: credentials.email } });
    },
  });

  return authFactory();
}
```

Register the secret in `nuxt.config.ts`:

```typescript
export default defineNuxtConfig({
  runtimeConfig: {
    idealAuthSecret: process.env.IDEAL_AUTH_SECRET,
  },
});
```

Files in `server/utils/` are auto-imported. Call `auth(event)` directly.

Login API route:

```typescript
// server/api/auth/login.post.ts
export default defineEventHandler(async (event) => {
  const body = await readBody(event);

  if (!body.email || !body.password) {
    throw createError({ statusCode: 400, statusMessage: 'Email and password are required.' });
  }

  const session = auth(event);
  const success = await session.attempt(
    { email: body.email, password: body.password },
    { remember: body.remember ?? false },
  );

  if (!success) {
    throw createError({ statusCode: 401, statusMessage: 'Invalid email or password.' });
  }

  return { success: true };
});
```

**CSRF:** Nuxt has NO built-in CSRF protection. Implement Origin header validation as server middleware, or use the `nuxt-security` module.

---

### TanStack Start

```typescript
// app/lib/cookies.ts
import { getCookie, setCookie, deleteCookie } from 'vinxi/http';
import type { CookieBridge } from 'ideal-auth';

export function createCookieBridge(): CookieBridge {
  return {
    get(name: string) {
      return getCookie(name);
    },
    set(name, value, options) {
      setCookie(name, value, options);
    },
    delete(name) {
      deleteCookie(name, { path: '/' });
    },
  };
}
```

**IMPORTANT:** `vinxi/http` cookie functions use async local storage — must be called within a `createServerFn` handler or server middleware.

Auth setup:

```typescript
// app/lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import { createCookieBridge } from './cookies';
import { db } from './db';

type User = { id: string; email: string; name: string; password: string };

export const hash = createHash({ rounds: 12 });

const authFactory = createAuth<User>({
  secret: process.env.IDEAL_AUTH_SECRET!,
  cookie: createCookieBridge(),
  hash,

  async resolveUser(id) {
    return db.user.findUnique({ where: { id } });
  },

  async resolveUserByCredentials(credentials) {
    return db.user.findUnique({ where: { email: credentials.email } });
  },
});

export function auth() {
  return authFactory();
}
```

Server functions:

```typescript
// app/lib/auth.actions.ts
import { createServerFn } from '@tanstack/start';
import { auth, hash } from './auth';
import { db } from './db';

export const loginFn = createServerFn({ method: 'POST' })
  .validator((data: { email: string; password: string; remember?: boolean }) => data)
  .handler(async ({ data }) => {
    if (!data.email || !data.password) throw new Error('Email and password are required.');

    const session = auth();
    const success = await session.attempt(
      { email: data.email, password: data.password },
      { remember: data.remember ?? false },
    );

    if (!success) throw new Error('Invalid email or password.');

    return { success: true };
  });

export const getCurrentUserFn = createServerFn({ method: 'GET' })
  .handler(async () => {
    const session = auth();
    const user = await session.user();

    if (!user) return { user: null };

    return { user: { id: user.id, email: user.email, name: user.name } };
  });
```

Route protection with `beforeLoad`:

```tsx
// app/routes/dashboard.tsx
import { createFileRoute, redirect } from '@tanstack/react-router';
import { getCurrentUserFn } from '../lib/auth.actions';

export const Route = createFileRoute('/dashboard')({
  beforeLoad: async () => {
    const { user } = await getCurrentUserFn();

    if (!user) {
      throw redirect({ to: '/login', search: { callbackUrl: '/dashboard' } });
    }

    return { user };
  },
  component: DashboardPage,
});

function DashboardPage() {
  const { user } = Route.useRouteContext();
  return <h1>Welcome, {user.name}</h1>;
}
```

**CSRF:** TanStack Start has NO built-in CSRF protection. Validate the Origin header manually.

---

### Elysia

```typescript
// src/lib/auth.ts
import { createAuth, createHash } from 'ideal-auth';
import type { Context } from 'elysia';
import { db } from './db';

export const hash = createHash({ rounds: 12 });

export function auth(ctx: Context) {
  const { cookie } = ctx;

  return createAuth({
    secret: process.env.IDEAL_AUTH_SECRET!,

    cookie: {
      get: (name) => cookie[name]?.value,
      set: (name, value, opts) => {
        cookie[name].set({
          value,
          httpOnly: opts.httpOnly,
          secure: opts.secure,
          sameSite: opts.sameSite,
          path: opts.path,
          maxAge: opts.maxAge,
        });
      },
      delete: (name) => cookie[name].remove(),
    },

    hash,

    resolveUser: async (id) => db.user.findUnique({ where: { id } }),

    resolveUserByCredentials: async (creds) =>
      db.user.findUnique({ where: { email: creds.email } }),
  });
}
```

**Note:** `auth(ctx)` returns the factory. Call `auth(ctx)()` to get the instance.

Auth middleware with `derive`:

```typescript
// src/middleware/auth.ts
import { Elysia } from 'elysia';
import { auth } from '../lib/auth';

export const requireAuth = new Elysia({ name: 'requireAuth' })
  .derive(async (ctx) => {
    const session = auth(ctx)();
    const user = await session.user();

    if (!user) {
      ctx.set.status = 401;
      throw new Error('Unauthorized');
    }

    return { user };
  });
```

**CSRF:** Elysia has no built-in CSRF. Validate Origin header via `onBeforeHandle`.

---

## Common Auth Flows

### Password Reset

```typescript
import { createTokenVerifier, createHash } from 'ideal-auth';

const passwordReset = createTokenVerifier({
  secret: process.env.IDEAL_AUTH_SECRET! + '-reset',  // use a different secret per use case
  expiryMs: 60 * 60 * 1000,  // 1 hour
});

// Step 1: User requests reset
const token = passwordReset.createToken(user.id);
await sendEmail(user.email, `https://app.com/reset/${token}`);
// Put token in URL path, NOT query string (query strings are logged)

// Step 2: User clicks link
const result = passwordReset.verifyToken(token);
if (!result) throw new Error('Invalid or expired token');

// Step 3: Validate token hasn't been used (CRITICAL — tokens are stateless)
if (result.iatMs < user.passwordChangedAt) {
  throw new Error('Token already used');
}

// Step 4: Update password
const hash = createHash();
await db.user.update({
  where: { id: result.userId },
  data: {
    password: await hash.make(newPassword),
    passwordChangedAt: Date.now(),
  },
});
```

### Email Verification

```typescript
const emailVerification = createTokenVerifier({
  secret: process.env.IDEAL_AUTH_SECRET! + '-email',
  expiryMs: 24 * 60 * 60 * 1000,  // 24 hours
});

// After registration
const token = emailVerification.createToken(user.id);
await sendEmail(user.email, `https://app.com/verify/${token}`);

// Verify
const result = emailVerification.verifyToken(token);
if (!result) throw new Error('Invalid or expired token');

await db.user.update({
  where: { id: result.userId },
  data: { emailVerifiedAt: new Date() },
});
```

### Two-Factor Authentication (TOTP)

**Setup phase:**

```typescript
import { createTOTP, createHash, encrypt, generateRecoveryCodes } from 'ideal-auth';

const totp = createTOTP();
const hash = createHash();

// 1. Generate secret
const secret = totp.generateSecret();

// 2. Create QR code URI
const uri = totp.generateQrUri({
  secret,
  issuer: 'MyApp',
  account: user.email,
});
// Render uri as QR code with any QR library

// 3. Verify user can produce a valid code
if (!totp.verify(codeFromAuthenticator, secret)) {
  throw new Error('Invalid setup code');
}

// 4. Store secret encrypted
await db.user.update({
  where: { id: user.id },
  data: {
    totpSecret: await encrypt(secret, process.env.ENCRYPTION_KEY!),
    totpEnabled: true,
  },
});

// 5. Generate recovery codes
const { codes, hashed } = await generateRecoveryCodes(hash, 8);
// Show codes to user ONCE, store hashed in DB
await db.user.update({
  where: { id: user.id },
  data: { recoveryCodes: hashed },
});
```

**Login with 2FA:**

```typescript
import { decrypt } from 'ideal-auth';

// After password verification, check if 2FA is enabled
if (user.totpEnabled) {
  const decryptedSecret = await decrypt(user.totpSecret, process.env.ENCRYPTION_KEY!);

  if (!totp.verify(codeFromUser, decryptedSecret)) {
    throw new Error('Invalid 2FA code');
  }
}

await auth().login(user);
```

**Recovery code login:**

```typescript
import { verifyRecoveryCode } from 'ideal-auth';

const { valid, remaining } = await verifyRecoveryCode(code, user.recoveryCodes, hash);
if (valid) {
  await db.user.update({
    where: { id: user.id },
    data: { recoveryCodes: remaining },
  });
  await auth().login(user);
}
```

### Rate-Limited Login (Next.js example)

```typescript
'use server';

import { redirect } from 'next/navigation';
import { headers } from 'next/headers';
import { auth } from '@/lib/auth';
import { createRateLimiter } from 'ideal-auth';

const limiter = createRateLimiter({
  maxAttempts: 5,
  windowMs: 60_000,  // 1 minute
});

export async function loginAction(formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

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

### Remember Me

```typescript
// Session cookie (expires when browser closes)
await auth().login(user, { remember: false });

// Default (7 days)
await auth().login(user);

// Persistent (30 days)
await auth().login(user, { remember: true });
```

---

## Open Redirect Prevention

Always validate redirect URLs after login. Never redirect to user-supplied absolute URLs.

```typescript
// lib/safe-redirect.ts
export function safeRedirect(url: string | null | undefined, fallback = '/'): string {
  if (
    !url ||
    !url.startsWith('/') ||
    url.startsWith('//') ||
    url.startsWith('/\\') ||
    url.includes('://')
  ) {
    return fallback;
  }

  return url;
}
```

Use it in login actions:

```typescript
import { safeRedirect } from '@/lib/safe-redirect';

// After successful login
redirect(safeRedirect(redirectTo, '/dashboard'));
```

---

## Security Rules

### Always enforced by ideal-auth:
- `httpOnly: true` on session cookies — forced at runtime, cannot be overridden
- `secure: true` when `NODE_ENV === 'production'`
- `sameSite: 'lax'` by default
- `path: '/'` by default
- Secret must be 32+ characters — throws at startup if shorter
- SHA-256 prehash for passwords > 72 bytes (prevents silent bcrypt truncation)
- Timing-safe comparison for all secret/signature/TOTP operations

### Your responsibility:
- CSRF protection (framework-dependent — see each framework section)
- Open redirect prevention (use `safeRedirect`)
- Password minimum length enforcement (NIST recommends 8+)
- Rate limiting on login, registration, and password reset endpoints
- Using a persistent rate limit store in production (not in-memory)
- Encrypting TOTP secrets at rest
- Checking `iatMs` on tokens to prevent reuse after password change
- Using different token secrets per use case
- Setting `NODE_ENV=production` in production
- Never logging passwords
- Using parameterized queries/ORM (SQL injection prevention)
- Content sanitization (XSS prevention)

### CSRF by framework:
| Framework | CSRF Protection |
|-----------|----------------|
| Next.js Server Actions | Built-in (automatic Origin validation) |
| Next.js API Routes | Manual Origin validation needed |
| SvelteKit form actions | Built-in (automatic Origin validation) |
| Hono | Built-in `csrf()` middleware |
| Express | Manual — implement Origin validation middleware |
| Nuxt | Manual — implement Origin validation or use `nuxt-security` |
| TanStack Start | Manual — validate Origin in server functions or middleware |
| Elysia | Manual — validate Origin in `onBeforeHandle` |

### Configuration Defaults

| Setting | Default | Notes |
|---------|---------|-------|
| Session secret | 32+ chars | Validated at startup |
| Cookie name | `ideal_session` | Customizable |
| Session maxAge | 604,800s (7 days) | Standard session |
| Remember maxAge | 2,592,000s (30 days) | Remember me |
| Cookie secure | `NODE_ENV === 'production'` | Auto |
| Cookie sameSite | `lax` | CSRF protection |
| Cookie path | `/` | Full domain |
| Cookie httpOnly | `true` | Forced, not configurable |
| Bcrypt rounds | 12 | ~250ms per hash |
| TOTP digits | 6 | Standard |
| TOTP period | 30s | RFC 6238 |
| TOTP window | 1 | ±1 step (~90s acceptance) |
| Token expiry | 3,600,000ms (1h) | Configurable |
| Rate limit store | MemoryRateLimitStore | Use Redis/DB in prod |

---

## Troubleshooting

### Session not persisting
- **Next.js 15+:** Ensure `cookies()` is `await`ed in the cookie bridge
- **Cookie bridge:** Ensure `set()` passes all three args (name, value, options) to the framework
- **Cookie path:** Default is `'/'` — if overridden, ensure it covers all routes

### Login works in dev but not production
- `IDEAL_AUTH_SECRET` must be set in production env vars
- Secret must be identical across all server instances/deploys
- `NODE_ENV=production` must be set (controls `secure` cookie flag)
- HTTPS must be enabled (secure cookies only sent over HTTPS)

### `attempt()` always returns false
- Check `resolveUserByCredentials` returns the user object (not null)
- Ensure user has a `password` field with a bcrypt hash (starts with `$2a$` or `$2b$`)
- If your password column is named differently, set `passwordField`
- If your credential key is not `password`, set `credentialKey`

### Cookie not set on localhost
- Don't set `secure: true` explicitly in dev (default is `false` when not production)
- `sameSite: 'none'` requires `secure: true`
- Frontend and API on different ports? Browser may block as third-party cookie

### TypeScript errors with user type
- Pass your user type as generic: `createAuth<User>({ ... })`
- User type must have `id: string | number`

### TOTP codes not verifying
- Server clock must be synced (use NTP)
- Don't set `window: 0` — too strict for real-world use
- Verify the TOTP secret round-trips correctly through storage

### Rate limiter not working in production
- `MemoryRateLimitStore` resets on process restart and is per-process
- Use Redis-backed store for serverless/multi-instance deployments

### Token verifier returns null
- Same secret must be used for creation and verification
- Check if token has expired (default: 1 hour)
- Secret rotation invalidates all outstanding tokens

---

## Production Checklist

Before deploying, verify:

- [ ] `IDEAL_AUTH_SECRET` is set, 32+ chars, not in version control
- [ ] `NODE_ENV=production` is set
- [ ] HTTPS is enabled
- [ ] Session `maxAge` is appropriate for your use case
- [ ] `httpOnly` is forced (default — do not strip in cookie bridge)
- [ ] `secure` cookie flag is `true` in production
- [ ] `sameSite` is `lax` (default) — only change if you understand the implications
- [ ] Bcrypt rounds are 12+ (default)
- [ ] Password minimum length is enforced (8+ characters)
- [ ] Passwords are never logged
- [ ] Login endpoint is rate limited
- [ ] Registration endpoint is rate limited
- [ ] Password reset endpoint is rate limited
- [ ] Using persistent rate limit store in production (not in-memory)
- [ ] CSRF protection is enabled for your framework
- [ ] Token secrets are 32+ chars, different per use case
- [ ] Token expiry is appropriate (reset: 1h, email: 24h, magic link: 15m)
- [ ] Tokens are in URL paths, not query strings
- [ ] Token `iatMs` is checked against relevant timestamps
- [ ] TOTP secret is stored encrypted in database
- [ ] Recovery codes are shown once, stored hashed
- [ ] Post-login redirects are validated with `safeRedirect`
- [ ] Error messages don't leak user existence ("Invalid email or password")
- [ ] Secret rotation plan exists for emergency session invalidation
