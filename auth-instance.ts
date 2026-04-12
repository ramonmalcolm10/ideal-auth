import type {
  AnyUser,
  AuthInstance,
  ConfigurableCookieOptions,
  CookieBridge,
  HashInstance,
  LoginOptions,
  SessionPayload,
} from './types';
import { seal, unseal } from './session/seal';
import { buildCookieOptions } from './session/cookie';

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
  let cachedUser: TUser | null | undefined;

  let didAutoTouch = false;

  async function readSession(): Promise<SessionPayload | null> {
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
    if (payload.data) {
      // sessionFields mode: cache only the picked fields
      cachedUser = { id: user.id, ...payload.data } as TUser;
    } else {
      // resolveUser mode: strip the password field from cache
      const { [deps.passwordField]: _, ...safeUser } = user as Record<string, any>;
      cachedUser = safeUser as TUser;
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
        if (!dbUser) return false;

        const storedHash = (dbUser as Record<string, any>)[deps.passwordField];
        if (!storedHash || !(await deps.hash.verify(password, storedHash))) {
          return false;
        }

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

    async user(): Promise<TUser | null> {
      if (cachedUser !== undefined) return cachedUser;

      const session = await readSession();
      if (!session) {
        cachedUser = null;
        return null;
      }

      // Cookie-backed: reconstruct user from session data
      if (deps.sessionFields && session.data) {
        cachedUser = { id: session.uid, ...session.data } as TUser;
        return cachedUser;
      }

      // Database-backed: resolve user via callback
      if (deps.resolveUser) {
        cachedUser = (await deps.resolveUser(session.uid)) ?? null;
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
