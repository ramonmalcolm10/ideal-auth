import type {
  AnyUser,
  AuthInstance,
  ConfigurableCookieOptions,
  CookieBridge,
  HashInstance,
  LoginOptions,
  SessionPayload,
  SessionUser,
} from './types';
import { seal, unseal } from './session/seal';
import { buildCookieOptions } from './session/cookie';

// Equalize attempt() timing between user-found and user-missing paths by always
// running hash.verify(). The dummy hash is cached per HashInstance so repeated
// misses match the cost of a real verify.
const dummyHashCache = new WeakMap<HashInstance, Promise<string>>();
function getDummyHash(hash: HashInstance): Promise<string> {
  let p = dummyHashCache.get(hash);
  if (!p) {
    p = hash.make('__ideal-auth-dummy__');
    dummyHashCache.set(hash, p);
  }
  return p;
}

interface AuthInstanceDeps<TUser extends AnyUser> {
  secret: string;
  cookie: CookieBridge;
  cookieName: string;
  maxAge: number;
  rememberMaxAge: number;
  cookieOptions: ConfigurableCookieOptions;
  autoTouch: boolean;
  resolveUser?: (id: string) => Promise<TUser | null | undefined>;
  sessionFields?: (keyof TUser & string)[];
  hash?: HashInstance;
  resolveUserByCredentials?: (
    credentials: Record<string, any>,
  ) => Promise<AnyUser | null | undefined>;
  credentialKey: string;
  passwordField: string;
  attemptUser?: (credentials: Record<string, any>) => Promise<TUser | null | undefined>;
}

export function createAuthInstance<TUser extends AnyUser>(
  deps: AuthInstanceDeps<TUser>,
): AuthInstance<TUser> {
  let cachedPayload: SessionPayload | null | undefined;
  let cachedUser: SessionUser<TUser> | null | undefined;

  let didAutoTouch = false;

  function validateSecret(): void {
    if (!deps.secret || deps.secret.length < 32) {
      throw new Error('secret must be at least 32 characters');
    }
  }

  async function readSession(): Promise<SessionPayload | null> {
    // Fail closed on reads — no secret means no session, not an error
    if (!deps.secret || deps.secret.length < 32) {
      cachedPayload = null;
      return null;
    }
    if (cachedPayload !== undefined) return cachedPayload;

    const raw = await deps.cookie.get(deps.cookieName);
    if (!raw) {
      cachedPayload = null;
      return null;
    }

    cachedPayload = await unseal(raw, deps.secret);

    // Auto-touch: reseal past halfway when enabled
    if (deps.autoTouch && cachedPayload && !didAutoTouch) {
      const elapsed = Math.floor(Date.now() / 1000) - cachedPayload.iat;
      if (elapsed >= cachedPayload.ttl / 2) {
        await resealSession(cachedPayload);
      }
    }

    return cachedPayload;
  }

  async function resealSession(session: SessionPayload): Promise<void> {
    didAutoTouch = true;
    const ttl = session.ttl;
    const now = Math.floor(Date.now() / 1000);
    const newPayload: SessionPayload = {
      uid: session.uid,
      iat: session.iat,  // preserve original issued-at for passwordChangedAt checks
      exp: now + ttl,
      ttl,
      ...(session.data !== undefined && { data: session.data }),
    };

    const sealed = await seal(newPayload, deps.secret);
    const opts = buildCookieOptions(ttl, deps.cookieOptions);
    await deps.cookie.set(deps.cookieName, sealed, opts);

    cachedPayload = newPayload;
  }

  function pickSessionData(user: TUser): Record<string, unknown> | undefined {
    if (!deps.sessionFields) return undefined;

    const data: Record<string, unknown> = {};
    for (const field of deps.sessionFields) {
      if (field !== 'id' && field in user) {
        data[field] = user[field];
      }
    }
    return Object.keys(data).length > 0 ? data : undefined;
  }

  async function writeSession(
    user: TUser,
    options?: LoginOptions,
  ): Promise<void> {
    validateSecret();
    const maxAge = options?.remember ? deps.rememberMaxAge : deps.maxAge;
    const now = Math.floor(Date.now() / 1000);
    const payload: SessionPayload = {
      uid: String(user.id),
      iat: now,
      exp: now + maxAge,
      ttl: maxAge,
      data: pickSessionData(user),
    };

    const sealed = await seal(payload, deps.secret);
    const opts = options?.remember === false
      ? buildCookieOptions(undefined, deps.cookieOptions)
      : buildCookieOptions(maxAge, deps.cookieOptions);
    await deps.cookie.set(deps.cookieName, sealed, opts);

    cachedPayload = payload;
    // Always coerce id to string so the same-request login path matches the
    // cross-request read path (cookie ids are always strings).
    if (payload.data) {
      // sessionFields mode: cache only the picked fields
      cachedUser = { ...payload.data, id: payload.uid } as SessionUser<TUser>;
    } else {
      // resolveUser mode: strip the password field from cache
      const { [deps.passwordField]: _, ...safeUser } = user as Record<string, any>;
      cachedUser = { ...safeUser, id: payload.uid } as SessionUser<TUser>;
    }
  }

  return {
    async login(user: TUser, options?: LoginOptions): Promise<void> {
      await writeSession(user, options);
    },

    async loginById(id: string, options?: LoginOptions): Promise<void> {
      if (!deps.resolveUser) {
        throw new Error('loginById requires resolveUser — use login(user) instead when using sessionFields');
      }
      const user = await deps.resolveUser(id);
      if (!user) throw new Error('Login failed');
      await writeSession(user, options);
    },

    async attempt(credentials: Record<string, any>, options?: LoginOptions): Promise<boolean> {
      // Escape hatch: attemptUser handles everything
      if (deps.attemptUser) {
        const user = await deps.attemptUser(credentials);
        if (!user) return false;
        await writeSession(user, options);
        return true;
      }

      // Laravel-style: strip password, resolve user, verify hash
      if (deps.hash && deps.resolveUserByCredentials) {
        const { [deps.credentialKey]: password, ...lookup } = credentials;
        const dbUser = await deps.resolveUserByCredentials(lookup);

        // Run verify even on miss against a dummy hash — prevents user enumeration via timing
        const storedHash = dbUser
          ? (dbUser as Record<string, any>)[deps.passwordField]
          : undefined;
        const hashToCheck = storedHash ?? (await getDummyHash(deps.hash));
        const ok = await deps.hash.verify(password, hashToCheck);

        if (!dbUser || !storedHash || !ok) return false;

        await writeSession(dbUser as TUser, options);
        return true;
      }

      throw new Error(
        'Provide either attemptUser() or both hash + resolveUserByCredentials in config to use attempt()',
      );
    },

    async logout(): Promise<void> {
      await deps.cookie.delete(deps.cookieName);
      cachedPayload = null;
      cachedUser = null;
    },

    async check(): Promise<boolean> {
      const session = await readSession();
      return session !== null;
    },

    async user(): Promise<SessionUser<TUser> | null> {
      if (cachedUser !== undefined) return cachedUser;

      const session = await readSession();
      if (!session) {
        cachedUser = null;
        return null;
      }

      // Cookie-backed: reconstruct user from session data
      if (deps.sessionFields && session.data) {
        cachedUser = { ...session.data, id: session.uid } as SessionUser<TUser>;
        return cachedUser;
      }

      // Database-backed: resolve user via callback, then normalize id to string
      if (deps.resolveUser) {
        const resolved = await deps.resolveUser(session.uid);
        if (!resolved) {
          cachedUser = null;
          return null;
        }
        cachedUser = { ...resolved, id: String(resolved.id) } as SessionUser<TUser>;
        return cachedUser;
      }

      cachedUser = null;
      return cachedUser;
    },

    async id(): Promise<string | null> {
      const session = await readSession();
      return session?.uid ?? null;
    },

    async touch(): Promise<void> {
      const session = await readSession();
      if (!session) return;
      if (didAutoTouch) return; // already resealed by autoTouch on this request

      // autoTouch enabled: reseal immediately (user opted in to cookie writes)
      // autoTouch disabled: only reseal past halfway (conservative)
      if (!deps.autoTouch) {
        const elapsed = Math.floor(Date.now() / 1000) - session.iat;
        if (elapsed < session.ttl / 2) return;
      }

      await resealSession(session);
    },
  };
}
